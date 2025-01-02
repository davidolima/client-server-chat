# TODO
# [X] cada cliente se comunica com o servidor, que gerenciara a comunicacao entre clientes
# [  ] cada cliente deve se cadastrar junto ao servidor como um usuario
# [X] cada cliente deve poder se comunicar com outro cliente usando o nome de usuario (semelhante ao que ocorre no WhatsApp atraves do numero de telefone)
# [  ] (OPCIONAL) clientes podem se juntar a grupos multicast (semelhante ao que ocorre no whatsapp)

import socket
import warnings
from typing import *
from time import sleep
import struct

import threading

import os

from crypto import Criptografia, MsgType

MSGLEN = 1024
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
        self.online_users = []

        self.host: str = ''
        self.port: int = -1

        self.msg_history = {}
        self.unread = []
        self.gui = None

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
        self.socket.connect( (self.host, self.port) )

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

    def sendFile(self, dst, filename) -> None:
        self.sendFilePackage(MsgType.FWDFL, dst, filename)
        self.registerMessage(self.dst, f"[!] Você enviou um arquivo para {dst}: {filename}")

    def sendFilePackage(self, msg_type: MsgType, dst: str, filename: str):
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return (MsgType.ERRMSG, '', '', '')

        enc_msg = Criptografia.encode_msg(msg_type, self.username, dst, f'received_{os.path.basename(filename)}')
        self.socket.sendall(enc_msg) 

        fsz = os.path.getsize(filename)
        self.socket.send(struct.pack('!I', fsz))

        # Enviando arquivo
        with open(filename, 'rb') as file:
            file_data = file.read(1024)          
            total_sent = 0
            while total_sent < fsz:
                sent = self.socket.send(file_data)
                if sent == 0:
                    raise RuntimeError("Socket connection broken.")
                total_sent += sent
                file_data = file.read(1024)
        file.close()  

    def sendMessage(self, dst, msg: str) -> None:
        self.sendPackage(MsgType.FWDMSG, dst, msg)
        self.registerMessage(self.dst, f"Você: {msg}")

    def sendPackage(self, msg_type: MsgType, dst: str, msg: str):
        """
        Baseado em: https://docs.python.org/3/howto/sockets.html
        """
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return
        assert(self.socket is not None)  # NOTE: Just so LSP works properly

        enc_msg = Criptografia.encode_msg(msg_type, self.username, dst, msg)
        try:
            self.socket.sendall(enc_msg)
            #print(f"Sent {len(enc_msg)} bytes: {MsgType.FWDMSG} {self.username} {dst} {msg}")
        except socket.error as e:
            print(f"[!] Conexão perdida. ({e})")
            print(f"[!] Tentando reconectar em {RECONNECT_TIMEOUT}s...")
            sleep(RECONNECT_TIMEOUT)
            self.reconnect()

    def receivePackage(self) -> tuple[MsgType, str,str,str]:
        """
        Baseado em: https://docs.python.org/3/howto/sockets.html
        """
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return (MsgType.ERRMSG, '', '', '')
        assert(self.socket is not None)

        data = self.socket.recv(1024)
        #print(data)
        msg_type, src, dst, msg = Criptografia.decode_msg(data)
        return msg_type, src, dst, msg

    def authenticate(self, username, passwd) -> bool:
        """
        Method used to authenticate users.
        The return value determines if the attempt was successful.
        """
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return False
        assert(self.socket is not None) # NOTE: Just so LSP works properly

        self.username = username.replace(' ', '_').replace('*','')
        assert(passwd == passwd) # FIXME: `passwd` is unused. Use it in authentication

        addr, port = self.socket.getsockname()
        self.sendPackage(MsgType.CONNCT, str(addr), str(port))
        mtype, _, _, msg = self.receivePackage()

        if mtype == MsgType.ACCEPT.value:
            return True
        elif mtype == MsgType.DENIED.value:
            print("[Error]", msg)
        else:
            print("Unexpected return type when trying to login:", mtype)
        return False

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

    def getDestination(self):
        return self.dst

    def setDestination(self, dst):
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
                data = self.socket.recv(1024)
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
            self.sendMessage(self.dst, msg)

    def interpretPackage(self, pkg) -> bool:
        mtype, src, dst, msg = pkg
        interrupt = False
        match(mtype):
            case MsgType.FWDMSG.value:
                self.registerMessage(src, f"{src}: {msg}")
            case MsgType.FWDFL.value:
                self.downloadReceivedFile(src, filename = msg)
            case MsgType.SERVER.value:
                self.registerMessage(self.dst, f"[SERVER] {msg}")
            case MsgType.ERRMSG.value:
                self.registerMessage(self.dst, f"[ERROR] The server reported an error: {msg}")
                interrupt = True
            case MsgType.DISCNT.value:
                self.registerMessage(self.dst, f"[SERVER] Disconnected from server: {msg}")
                interrupt = True
            case MsgType.USRONL.value:
                self.online_users = msg[2:-3].split("', '")
                self.notifyGUI()
            case _:
                pass
        return interrupt

    def start_receive_loop(self):
        def receive_messages():
            while self.isConnected():
                if self.interpretPackage( self.receivePackage() ):
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

        if not self.authenticate(username=username, passwd=''):
            print("[!] A autenticação falhou.")
            return

        self.start_receive_loop()
        while True:
            if (self.dst is None):
                usr = input("Escolha um usuário para conversar: ")
                if usr.startswith('\\'):
                    self.interpretMessage(usr)
                self.dst = usr
                self.getMsgHistoryWithUsr(self.dst) # iniciar histórico de conversa com dst

            else:
                msg = input(f"> ")
                print('\033[1A' + '\033[K', end='')
                self.interpretMessage(msg)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=socket.gethostname(), type=str)
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()

    Cliente().startInTerminal(args.host, args.port)
