# TODO: clientes podem se juntar a grupos multicast (semelhante ao que ocorre no whatsapp)

import os
import struct
import socket
import warnings
import threading
from time import sleep

from typing import *

import rsa
from crypto import Criptografia, MsgType
from crypto import PKG_SIZE, PKG_CHUNK_SIZE

RECONNECT_TRIES = 3
RECONNECT_TIMEOUT = 5

class Cliente:
    """
    Classe cliente.
    """

    def __init__(self):
        self.socket = None
        self.username = "user"
        self.dst = None
        self.online_users = {}

        self.host: str = ''
        self.port: int = -1

        self.pub_rsa_key, self.priv_rsa_key = Criptografia.generate_rsa_keys()
        self.server_pub_key = None

        self.msg_history = {}
        self.unread = []
        self.gui = None

        self.recv_msgs = True

    def registerGUI(self, gui):
        """
        Register GUI as observer
        """
        self.gui = gui

    def notifyGUI(self):
        if self.gui is not None:
            self.gui.update()

    def isConnected(self) -> bool:
        return (self.socket is not None)

    def connect(self, host: str, port: int) -> None:
        if self.isConnected():
            warnings.warn("Already connected!")
            return

        self.host, self.port = host, port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect( (self.host, self.port) )
        except ConnectionRefusedError:
            print(F"[ERROR] Error connecting to {self.host}:{self.port}: Server is offline.")
            quit(0)

        # Trade RSA keys with server
        pubkey = Criptografia.str_from_pubkey(self.getPublicKey())
        self.sendPackage(MsgType.CONNCT, f"{self.host}:{self.port}", pubkey, encrypt=False)

        mtype, _, _, msg = self.receivePackage(decrypt=True)
        if mtype == MsgType.ACCEPT:
            self.server_pub_key = Criptografia.pubkey_from_str(msg)
        elif mtype == MsgType.DENIED:
            print("[Error]", msg)
            quit(0)
        else:
            print("Unexpected return type when trying to login:", mtype)

    def disconnect(self) -> None:
        if not self.isConnected():
            warnings.warn("Attempted to disconnect without a connection.")
            return
        assert (self.socket is not None) # NOTE: Just so LSP works properly

        print("Desconectando...")
        self.socket.shutdown(0)
        self.socket.close()
        self.socket = None
        print("Desconectado!")
        quit(0)

    def reconnect(self):
        tries = RECONNECT_TRIES
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        while tries > 0:
            print(f"({RECONNECT_TRIES-tries+1}/{RECONNECT_TRIES}) Tentando reconectar...", end=' ')
            try:
                self.socket.connect( (self.host, self.port) )
                print("Reconectado!")
                return
            except socket.error as e:
                print(f"Falha ao conectar. ({e})")
                sleep( RECONNECT_TIMEOUT )
                tries -= 1

        print("Desconectado.")
        quit(0)

    def createGroup(self, name:str, users: list[str]):
        print(f"New group `>{name}`:", users)
        self.online_users['>'+name] = users
        self.notifyGUI()

    def sendFile(self, dst, filename) -> None:
        self.sendFilePackage(dst, filename)
        self.registerMessage(self.dst, f"[!] Você enviou um arquivo para {dst}: {filename}")

    def sendFilePackage(self, dst: str, filename: str):
        if not self.isConnected():
            warnings.warn("Not connected to server. Trying to reconnect.")
            self.reconnect()
            return (MsgType.ERRMSG, '', '', '')

        self.sendPackage(MsgType.FWDFL, dst, f'received_{os.path.basename(filename)}')

        fsz = os.path.getsize(filename)
        self.socket.send(struct.pack('!I', fsz))

        # Enviando arquivo
        with open(filename, 'rb') as file:
            file_data = file.read(PKG_SIZE)
            total_sent = 0
            while total_sent < fsz:
                sent = self.socket.send(file_data)
                if sent == 0:
                    raise RuntimeError("Socket connection broken.")
                total_sent += sent
                file_data = file.read(PKG_SIZE)
        file.close()  

    def getUsrPubKey(self, usr) -> rsa.PublicKey | None:
        if usr == 'server':
            return self.server_pub_key
        elif usr not in self.online_users.keys():
            return
        return self.online_users[usr]

    def sendMessage(self, dst, msg: str) -> None:
        self.sendPackage(MsgType.FWDMSG, dst, msg, encrypt=True)
        self.registerMessage(self.dst, f"Você: {msg}") #TODO: Register sent message only when server acknoledges it

    def sendPackage(self, msg_type: MsgType, dst: str, msg: str, encrypt=False):
        """
        Baseado em: https://docs.python.org/3/howto/sockets.html
        """
        if not self.isConnected():
            warnings.warn("Not connected to server. Trying to reconnect.")
            self.reconnect()
            return
        assert(self.socket is not None)  # NOTE: Just so LSP works properly

        dst_pubkey = None
        if encrypt:
            if msg_type in (MsgType.RGUSR, MsgType.CKLG):
                dst_pubkey = self.server_pub_key
            else:
                dst_pubkey = self.getUsrPubKey(dst)
                assert dst_pubkey is not None

        enc_msg = Criptografia.packMessage(msg_type, self.username, dst, msg, dst_pubkey)
        try:
            self.socket.sendall(enc_msg)
            #print(f"CLIENT SENT {len(enc_msg)} BYTES: {msg_type} {self.username} {dst} {msg}")
            #print(enc_msg)
        except socket.error as e:
            print(f"[!] Conexão perdida. ({e})")
            print(f"[!] Tentando reconectar em {RECONNECT_TIMEOUT}s...")
            sleep(RECONNECT_TIMEOUT)
            self.reconnect()

    def receivePackage(self, decrypt: bool = True) -> tuple[MsgType, str, str, str]:
        """
        Baseado em: https://docs.python.org/3/howto/sockets.html
        """
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return (MsgType.ERRMSG, '', '', '')
        assert(self.socket is not None)

        pkg = b''
        total_received = 0
        while total_received < PKG_SIZE:
            try:
                data = self.socket.recv(min(PKG_CHUNK_SIZE, PKG_SIZE-total_received))
                if not data:
                    break
                pkg += data
                total_received += len(data)
            except socket.error as e:
                print(f"Socket error while receiving: {e}")
                return (MsgType.ERRMSG, '', '', f'Socket error: {e}')

        if total_received < PKG_SIZE:
            pkg += b'\0' * (PKG_SIZE - total_received)

        msg_type, src, dst, msg = Criptografia.unpackMessage(pkg, None)
        should_decrypt = decrypt and (self.priv_rsa_key is not None) and (msg_type != MsgType.FWDFL)

        #print(f"CLIENT RECEIVED {len(pkg)} BYTES:", pkg)
        if should_decrypt:
            msg_type, src, dst, msg = Criptografia.unpackMessage(pkg, self.priv_rsa_key)

        #print(f"msg_type={msg_type} src={src} dst={dst} msg={msg}")
        return msg_type, src, dst, msg

    def registerUser(self, username, passwd) -> str:
        self.sendPackage(MsgType.RGUSR, username, passwd, encrypt=True)
        mtype, _, _, msg = self.receivePackage(decrypt=True)
        if mtype == MsgType.ACCEPT:
            return ''
        else:
            return str(msg)

    def authenticate(self, username, passwd) -> bool:
        """
        Method used to authenticate users.
        The return value determines if the attempt was successful.
        """
        if not self.isConnected():
            warnings.warn("Not connected to server. Trying to reconnect.")
            self.reconnect()
            return False
        assert(self.socket is not None) # NOTE: Just so LSP works properly

        self.username = username.replace(' ', '_').replace('*', '').replace('>', '')
        self.sendPackage(MsgType.CKLG, username, passwd, encrypt=True)
        mtype, _, _, msg = self.receivePackage(decrypt=False)
        if mtype == MsgType.ACCEPT:
            print(f"[SERVER] {msg}")
            return True

        print(f"[ERRO DE LOGIN] {msg}")
        return False

    def getPublicKey(self) -> rsa.PublicKey:
        return self.pub_rsa_key

    def getCachedOnlineUsers(self) -> list[str]:
        return list(self.online_users.keys())

    def registerMessage(self, author, msg):
        self.getMsgHistoryWithUsr(author)
        self.msg_history[author].append(msg)

        if self.dst != author and author not in self.unread:
            self.unread.append(author)

        if self.gui is None:
            print(msg)
        else:
            self.notifyGUI()

    def getUnread(self):
        return self.unread

    def getMsgHistory(self):
        return self.msg_history

    def getMsgHistoryWithUsr(self, usr):
        if usr not in self.msg_history.keys():
            self.msg_history[usr] = []
        return self.msg_history[usr]

    def getUsername(self) -> str:
        return self.username

    def getDestination(self) -> str | None:
        return self.dst

    def setDestination(self, dst) -> None:
        self.dst = dst
        if self.dst in self.unread:
            self.unread.remove(self.dst)

    def getFileSize(self) -> int:
        received = 0
        chunks = []
        while received < 4:
            data = self.socket.recv(4 - received)
            received += len(data)
            chunks.append(data)
        fsz = struct.unpack('!I', b''.join(chunks))[0]
        return fsz
    
    def downloadReceivedFile(self, src, filename):
        dst_path = os.path.join("received_files", src)
        if not os.path.exists('received_files'):
            os.mkdir('received_files')
        if not os.path.exists(dst_path):
            os.mkdir(dst_path)

        fpath = os.path.join(dst_path, filename.replace('\x00', ''))

        fsz = self.getFileSize()
        total_received = 0
        with open(fpath, 'wb') as file:
            while total_received < fsz:
                data = self.socket.recv(PKG_SIZE)
                if not data:
                    break
                file.write(data)
                total_received += len(data)
        file.close()
        self.registerMessage(self.dst, f"[!] {src} te enviou um arquivo: {filename}")

    def interpretMessage(self, msg: str) -> None:
        if msg.startswith('\\'): # Comandos
            if msg == '\\q': # Sair
                if self.dst is not None: # De conversas
                    self.dst = None
                else: # Do programa (desconectar)
                    self.disconnect()
                    quit()
            elif msg[:msg.find(' ')] == '\\send': # Enviar arquivo
                filename = msg[msg.find(' ')+1:]
                self.sendFile(self.dst, filename)
        else:
            assert self.dst is not None
            if (self.dst.startswith('>')): # It's a group
                for usr in self.online_users[self.dst]:
                    self.sendMessage(usr, msg)
            else:
                self.sendMessage(self.dst, msg)

    def interpretPackage(self, pkg) -> bool:
        mtype, src, dst, msg = pkg
        interrupt = False
        match(mtype):
            case MsgType.FWDMSG:
                self.registerMessage(src, f"{src}: {msg}")
            case MsgType.FWDFL:
                self.downloadReceivedFile(src, filename = msg)
            case MsgType.SERVER:
                self.registerMessage(self.dst, f"[SERVER] {msg}")
            case MsgType.ERRMSG:
                self.registerMessage(self.dst, f"[ERROR] The server reported an error: {msg}")
                interrupt = True
            case MsgType.DISCNT:
                self.registerMessage(self.dst, f"[SERVER] Disconnected from server: {msg}")
                interrupt = True
            case MsgType.USRONL:
                self.online_users = Cliente.parse_online_users(msg)
                #print(self.online_users)
                self.notifyGUI()
            case _:
                pass
        return interrupt

    def start_receive_loop(self):
        def receive_messages():
            while self.isConnected() and self.recv_msgs:
                if self.interpretPackage( self.receivePackage(decrypt=True) ):
                    break
            self.disconnect()

        thread = threading.Thread(target=receive_messages, daemon=True)
        thread.start()

    def start(self, server_addr, server_port):
        """
        Even though this method is only serving as an alias for self.connect,
        I'll keep it. This is because we might want to do something else
        during start-up.
        """
        self.connect(server_addr, server_port)

    def startInTerminal(self, server_addr, server_port):
        self.start(server_addr, server_port)
        print("Por favor, autentique-se:")
        username = input("Usuário: ")
        passwd   = input("Senha: ")

        if not self.authenticate(username=username, passwd=passwd):
            print("[!] A autenticação falhou.")
            return

        self.start_receive_loop()
        while True:
            if (self.dst is None):
                print("Usuários online:", self.getCachedOnlineUsers())
                usr = input("Escolha um usuário para conversar: ")
                if usr.startswith('\\'):
                    self.interpretMessage(usr)
                self.dst = usr
                self.getMsgHistoryWithUsr(self.dst) # iniciar histórico de conversa com dst

            else:
                msg = input(f"> ")
                print('\033[1A' + '\033[K', end='')
                self.interpretMessage(msg)

    @staticmethod
    def parse_online_users(online_usrs_package: str) -> Dict[str, rsa.PublicKey]:
        # this monstrosity parses a string of structure
        # "[('a', PrivateKey(12312,1231), ('b', PrivateKey(412321,1231231)))]"
        # And returns the values as a list of tuples.
        names_and_keys = [x.split(',PublicKey') for x in online_usrs_package.replace(' ', '').replace('\'','')[2:-2].split("),(")]
        return {usr: Criptografia.pubkey_from_str(pubkey_str) for usr,pubkey_str in names_and_keys}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default='localhost', type=str)
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()

    Cliente().startInTerminal(args.host, args.port)
