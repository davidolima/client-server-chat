import os
import socket
import threading
import struct
import json
from typing import *

import rsa

from crypto import Criptografia, MsgType
from crypto import PKG_SIZE, PKG_CHUNK_SIZE

MAX_CLIENTS_PER_HOST = 3

class Servidor():
    """
    Classe do servidor.
    Baseado em: https://docs.python.org/3/howto/sockets.html
    """
    def __init__(self, address, max_connections = 5):
        self.max_connections = max_connections

        self.online_users = {}
        self.user_reg_file = "./registers.json"

        self.log("Setting up server...")
        self.socket = self._init_socket(address)
        self.rsa_pubkey, self.rsa_privkey = Criptografia.generate_rsa_keys()
        self.log(f"Server is up on address {address[0]}:{address[1]}. Waiting for connections...")

    def _init_socket(self, address) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(address)
        s.listen(self.max_connections);
        return s

    def checkHostLimitPerClient(self, client_address: str) -> bool:
        """
        Returns True if there are less or MAX_CLIENTS_PER_HOST
        connected to server. Otherwise, returns False.
        """
        online_addresses = [v[1][0] for k,v in self.online_users.items()]
        client_host = client_address.strip().split(':')[0]

        if client_host == socket.gethostname() or client_host == 'localhost':
            client_host = '127.0.0.1'

        return (online_addresses.count(client_host) < MAX_CLIENTS_PER_HOST)

    def log(self, msg, logtype: Literal['server', 'info', 'warn'] | str = 'SERVER', **args):
        if logtype == 'warn':
            prefix = "[WARNING]"
        elif logtype == 'info':
            prefix = "[INFO]"
        else:
            prefix = f"[{logtype}]"

        print(prefix, msg, **args)

    def logPackage(self, msg_type: MsgType | int, src: str , dst: str, msg: str | bytes):
        msg_type = msg_type if type(msg_type) == MsgType else MsgType(msg_type)
        match (msg_type):
            case MsgType.FWDMSG:
                self.log(f"{src} -> {dst} ({len(msg)} bytes): {msg}", logtype=msg_type.name)
            case MsgType.FWDFL:
                self.log(f"{src} -> {dst} file of {msg} bytes.", logtype=msg_type.name)
            case MsgType.DISCNT:
                self.log(f"User {src} disconnected.", logtype=msg_type.name)
            case MsgType.CONNCT:
                self.log(f"{src} wants to connect.", logtype=msg_type.name)
                self.log(f"ADDRESS={dst} PUBKEY={msg}")
            case MsgType.RGUSR:
                self.log(f"Solicitation to register new user: `{dst}`.", logtype=msg_type.name)
                self.log(f"USERNAME={dst} PASSWD={msg}")
            case MsgType.CKLG:
                self.log(f"Solicitation to validate credentials from {src}.", logtype=msg_type.name)
                self.log(f"USERNAME={dst} PASSWD={msg}")
            case _:
                self.log(f"[{msg_type.name}] {src} -> {dst}: {msg}")

    def forwardMessage(self, src, dst, msg):
        if dst not in self.getOnlineUsers():
            self.sendPackageUsr(MsgType.SERVER, 'server', src, f"Cannot forward message. User `{dst}` is not online.")
            return

        #self.log(f"Forwarding message: src: {src} dst: {dst} msg: {msg}")
        self.sendPackageUsr(MsgType.ACCEPT, 'server', src, 'OK')
        self.sendPackageUsr(MsgType.FWDMSG, src, dst, msg)

    def sendPackage(self, socket: socket.socket, msg_type: MsgType, src: str, dst: str, msg: str, pubkey: rsa.PublicKey | None = None):
        pkg = Criptografia.packMessage(msg_type, src, dst, msg, pubkey if pubkey else None)

        total_sent = 0
        while total_sent < len(pkg):
            sent = socket.send(pkg[total_sent:])
            if not sent:
                raise RuntimeError("Socket connection broken.")
            total_sent += sent

        self.log(f"[{msg_type.name}] {src} -> {dst} ({len(msg)} bytes): {msg}", logtype="PACKAGE SENT")

    def sendPackageUsr(self, msg_type: MsgType, src: str, dst:str, msg:str) -> None:
        if dst not in self.getOnlineUsers():
            self.sendPackageUsr(MsgType.SERVER, 'server', src, f"Cannot send package. User `{dst}` is not online.")
            return

        # Do not encrypt messages that are being forwarded.
        # They are encrypted before being sent by the client.
        if msg_type in (MsgType.FWDMSG, MsgType.FWDFL):
            self.sendPackage(self.getUserSocket(dst), msg_type, src, dst, msg)
        else:
            self.sendPackage(self.getUserSocket(dst), msg_type, src, dst, msg, pubkey=self.getUserPubKey(dst))

    def sendToAll(self, msg_type: MsgType, src: str, msg: str):
        for usr in self.online_users.keys():
            self.sendPackageUsr(msg_type, src, usr, msg)

    def getUserSocket(self, usr) -> socket.socket:
        try:
            return self.online_users[usr][0]
        except KeyError:
            raise KeyError(f"User `{usr}` is not online. Unable to find public key.")

    def getUserAddr(self, usr) -> Tuple[str, int]:
        try:
            return self.online_users[usr][1]
        except KeyError:
            raise KeyError(f"User `{usr}` is not online. Unable to find address.")

    def getUserPubKey(self, usr) -> rsa.PublicKey:
        try:
            return self.online_users[usr][2]
        except KeyError:
            raise KeyError(f"User `{usr}` is not online. Unable to find public key.")

    def getServerPubKey(self) -> rsa.PublicKey:
        return self.rsa_pubkey

    def registerUser(self, socket: socket.socket, username: str, passwd: str, pubkey: rsa.PublicKey):
        """
        Registra um usuário no no arquivo de registros
        """

        with open(self.getUserRegFile()) as f:
            data = json.load(f)

        for usuario in data:
            if usuario['username'] == username:
                self.sendPackage(socket, MsgType.DENIED, 'server', username, f'Nome de usuário {username} já existe.', pubkey=pubkey)
                f.close()
                self.log(f'Cadastro falhou! Usuário {username} já existe.', logtype='info')
                return False
            
        data.append({'username': username, 'password': passwd})

        with open(self.getUserRegFile(), 'w') as f:
            json.dump(data, f)

        self.sendPackage(socket, MsgType.ACCEPT, 'server', username, f'Usuário {username} registrado com sucesso.', pubkey=pubkey)

        f.close()
        self.log(f'Usuario {username} cadastrado.')
        return True

    def checkUserCredentials(self, socket: socket.socket, username: str, passwd: str):
        """
        Verifica se as credenciais do usuário são válidas
        """
        with open('registers.json') as f:
            data = json.load(f)
        for usuario in data:
            if usuario['username'] == username and usuario['password'] == passwd:
                self.sendPackage(socket, MsgType.ACCEPT, 'server', username, 'Credenciais verificadas.')
                f.close()
                return True
        f.close()
        self.sendPackage(socket, MsgType.DENIED, 'server', username, 'Credenciais inválidas.')
        return False

    def authenticateClient(self, socket, username, passwd, addr, pubkey) -> bool:
        success = False
        if self.checkUserCredentials(socket = socket, username = username, passwd = passwd):
            self.online_users[username] = (socket, addr, pubkey)

            # notify clients
            self.sendToAll(MsgType.SERVER, 'server', f"{username} se conectou!")
            self.sendToAll(MsgType.USRONL, 'server', str(self.getOnlineUsers(pubkeys=True)))

        return success

    def connectClient(self, socket) -> tuple[str, rsa.PublicKey]:
        msg_type, usr, addr, pubkey = self.receivePackage(socket)

        if (msg_type == MsgType.CONNCT):
            pubkey = Criptografia.pubkey_from_str(pubkey)

            if not self.checkHostLimitPerClient(addr):
                self.sendPackage(
                    socket,
                    msg_type=MsgType.DENIED,
                    src='server',
                    dst=usr,
                    msg=f"Max number of connected clients exceeded for host `{addr.split(':')[0]}`.",
                    pubkey=pubkey
                )
                self.log(f"Max number of connected clients exceeded for host `{addr.split(':')[0]}`.", logtype="DENIED")
                return '', None
            else:
                self.sendPackage(
                    socket,
                    msg_type=MsgType.ACCEPT,
                    src='server',
                    dst=usr,
                    msg=Criptografia.str_from_pubkey(self.getServerPubKey()),
                    pubkey=pubkey
                )
        return usr, pubkey

    def removeUser(self, usr_addr):
        for k, v in self.online_users.items():
            if v[1] == usr_addr:
                self.online_users.pop(k)
                break

        print(self.getOnlineUsers(pubkeys=True))
        # notify clients
        self.sendToAll(MsgType.USRONL, 'server', str(self.getOnlineUsers(pubkeys=True)))

    def getOnlineUsers(self, pubkeys=False):
        if pubkeys:
            return [(k,v[2]) for k,v in self.online_users.items()]
        return list(self.online_users.keys())
    
    def sendFileUsr(self, src: str, dst: str, fnm: str, file_data: bytes):
        if dst not in self.online_users:
            self.sendPackageUsr(MsgType.ERRMSG, 'server', src, f"Cannot forward message; user `{dst}` is not online.")
            return
        
        client_socket = self.getUserSocket(dst)
        if client_socket._closed:
            self.log(f"Socket for user `{dst}` is closed. Unable to forward message.", logtype='warn')
            return

        # Envia informações da transação
        self.sendPackageUsr(MsgType.FWDFL, src, dst, fnm.replace('\x00', ''))

        # Envia tamanho do arquivo
        fsz = len(file_data)
        client_socket.send(struct.pack('!I', fsz))

        # Envia dados do arquivo
        total_sent = 0
        while total_sent < fsz:
            end = min(total_sent + PKG_SIZE, fsz)  # Define o tamanho do próximo bloco
            data = file_data[total_sent:end]
            sent = client_socket.send(data)
            if sent == 0:
                raise RuntimeError("Socket connection broken.")
            total_sent += sent
        self.logPackage(MsgType.FWDFL, src, dst, total_sent)
    
    def getFileSize(self, sock) -> int:
        received = 0
        chunks = []
        while received < 4:
            data = sock.recv(4 - received)
            received += len(data)
            chunks.append(data)
        fsz = struct.unpack('!I', b''.join(chunks))[0]
        return fsz
    
    def recieveFilePackage(self, src, dst, fnm):
        if dst not in self.online_users:
            self.sendPackageUsr(MsgType.ERRMSG, 'server', src, f"Cannot forward message; user `{dst}` is not online.")
            return
        
        src_socket = self.getUserSocket(src)
        fsz = self.getFileSize(src_socket)

        # Recebe o arquivo
        chunks = b''
        total_received = 0
        while total_received < fsz:
            data = src_socket.recv(PKG_SIZE)
            if not data:
                break
            chunks += data
            total_received += len(data)
        
        self.sendPackageUsr(MsgType.ACCEPT, 'server', src, 'OK')
        self.sendFileUsr(src, dst, fnm, chunks)

    def receivePackage(self, socket: socket.socket):
        pkg = b""
        total_received = 0
        while total_received < PKG_SIZE:
            data = socket.recv(PKG_CHUNK_SIZE)
            if not data:
                break
            pkg += data
            total_received += len(data)

        #print(f"SERVER RECEIVED {len(pkg)} BYTES:", pkg)
        msg_type, src, dst, msg = Criptografia.unpackMessage(pkg)
        if msg_type in (MsgType.RGUSR, MsgType.CKLG):
            msg_type, src, dst, msg = Criptografia.unpackMessage(pkg, self.rsa_privkey)

        self.logPackage(msg_type,src,dst,msg)
        return msg_type, src, dst, msg

    def interpretCommand(self, cmd, args):
        match (cmd):
            case "kick":
                """
                Kicks user of username args[0]
                """
                if len(args) != 1:
                    self.log(" Comando utilizado incorretamente. ", logtype='info')
                    self.log(" Ex: > kick david", logtype='info')
                    return
                elif args[0] not in self.getOnlineUsers():
                    self.log(f" Usuário `{args[0]}` não está online.", logtype='info')
                    return

                self.sendPackageUsr(MsgType.DISCNT, 'server', args[0], "kicked from server.")
                self.log(f"Kicked {args[0]}.")

            case "list":
                """
                Lists online users
                """
                self.log("Online users:", str(self.getOnlineUsers()))

            case _:
                self.log(f"Comando não reconhecido: `{cmd}`", logtype='info')

    def connectionLoop(
            self,
            client_socket: socket.socket,
            client_addr: tuple[str, int],
            user: str,
            pubkey: rsa.PublicKey,
    ) -> None:
        running = True
        while running:
            mtype, src, dst, msg = self.receivePackage(client_socket)
            match (mtype):
                case MsgType.DISCNT:
                    running = False

                case MsgType.FWDMSG:
                    assert(type(src) == str and type(dst) == str)
                    self.forwardMessage(src, dst, msg)

                case MsgType.FWDFL:
                    assert(type(src) == str and type(dst) == str and type(msg) == str)
                    self.recieveFilePackage(src, dst, fnm = msg)

                case MsgType.RGUSR:
                    self.registerUser(client_socket, username = dst, passwd = msg, pubkey=pubkey)

                case MsgType.CKLG:
                    self.authenticateClient(client_socket, dst, msg, client_addr, pubkey)

                case _:
                    self.log(f"Unknown message type received from user `{src}`: `{mtype}`. Disconnecting.", logtype='warn')
                    running = False

    def onClientConnect(self, client_socket: socket.socket, client_addr: tuple[str, int]):
        assert self.socket is not None, "Server is not ready to be receiving connections."

        self.log(f" >>> {client_addr} connected.")

        user, pubkey = self.connectClient(client_socket)
        if user is None or pubkey is None:
            return

        try:
            self.connectionLoop(client_socket, client_addr, user, pubkey)

        except Exception as e:
            self.log(f"Error handling client {client_addr}: {e}", logtype="warn")

        finally:
            client_socket.close()
            self.removeUser(client_addr)
            self.log(f" <<< {client_addr} disconnected.")

    def getUserRegFile(self) -> str:
        # Create user reg file if it doesn't exist
        if not os.path.exists(self.user_reg_file):
            with open(self.user_reg_file, 'w') as f:
                f.write('[]')

        return self.user_reg_file

    def start(self):
        while True:
            (c_socket, c_address) = self.socket.accept()
            client_thread = threading.Thread(
                target=self.onClientConnect,
                args=(c_socket, c_address),
                daemon=True
            )
            client_thread.start()

    def startWithTerminal(self):
        server_thread = threading.Thread(
                target=self.start,
                daemon=True
        )
        server_thread.start()

        while True:
            cmd = input("> ").split(' ')
            args = []
            if len(cmd) > 1:
                args = cmd[1:]
            self.interpretCommand(cmd[0], args)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default='localhost', type=str)
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()

    serv = Servidor((args.host, args.port))
    serv.startWithTerminal()
