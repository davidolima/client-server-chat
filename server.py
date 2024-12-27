# TODO
#  - criar um servidor para implementar as funcionalidades e requisitos do projeto

import socket
from typing import *
import warnings

from crypto import Criptografia, MsgType

ADDRESS = (socket.gethostname(), 8080)

class Servidor():
    """
    Classe do servidor.
    Baseado em: https://docs.python.org/3/howto/sockets.html
    """
    def __init__(self, address, max_connections = 5):
        self.max_connections = max_connections

        self.online_users = {}

        self.log("Setting up server...")
        self.socket = self._init_socket(address)
        self.log("Server is up. Waiting for connections...")

    def _init_socket(self, address) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(address)
        s.listen(self.max_connections);
        return s

    def log(self, msg, logtype: Literal['info', 'warn'] = 'info', **args):
        if logtype == 'warn':
            print("[SERVER WARNING]", msg, **args)
        else:
            print("[SERVER]", msg, **args)

    def forwardMessage(self, src, dst, msg):
        self.log(f"Forwarding message: src: {src} dst: {dst} msg: {msg}")
        self.sendPackageUsr(MsgType.FWDMSG, src, dst, msg)

    def sendPackageUsr(self, msg_type: MsgType, src: str , dst: str, msg: str):
        if dst not in self.getOnlineUsers():
            warnings.warn(f"{dst} can't be reached.")
        enc_msg = Criptografia.encode_msg(msg_type, src, dst, msg)

        client_socket = self.getUserSocket(dst)

        total_sent = 0
        while total_sent < len(msg):
            sent = client_socket.send(enc_msg[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken.")
            total_sent += sent
        self.log(f"{src} -> {dst} ({len(msg)} bytes) {msg}")

    def sendToAll(self, msg_type: MsgType, src: str , dst: str, msg: str):
        if dst not in self.getOnlineUsers():
            warnings.warn(f"{dst} can't be reached.")
        enc_msg = Criptografia.encode_msg(msg_type, src, dst, msg)

        total_sent = 0
        while total_sent < len(msg):
            sent = self.socket.send(enc_msg[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken.")
            total_sent += sent
        self.log(f"[{src} -> {dst}] ({len(msg)} bytes): {msg}")

    def getUserSocket(self, usr):
        return self.online_users[usr][0]

    def getUserAddr(self, usr):
        return self.online_users[usr][1]

    def addUser(self, usr, socket, addr):
        if usr not in self.online_users:
            self.log(f"User just connected: {usr}@{addr[0]}:{addr[1]}")
            self.online_users[usr] = (socket,addr)
            self.sendPackageUsr(MsgType.ACCEPT, 'server', usr, f'Conectado com servidor. Usuários online: {self.getOnlineUsers()}')
            return
        self.sendPackageUsr(MsgType.DENIED, 'server', usr, 'Nome de usuário já existe no servidor')

    def removeUser(self, usr):
        self.online_users.pop(usr)

    def getOnlineUsers(self):
        return list(self.online_users.keys())

    def interpretServerRequest(self, src:str, cmd: str, options: str):
        self.sendPackageUsr(MsgType.ACCEPT, src, cmd, str(list(__dict__.keys())))

    def interpretMessage(self, mtype: MsgType, src: str, dst: str, msg: str):
        match (mtype):
            case MsgType.CONNCT.value:
                self.addUser(src, socket=dst, addr=msg)
            case MsgType.DISCNT.value:
                self.removeUser(src)
            case MsgType.FWDMSG.value:
                self.log("FWDMSG")
                self.forwardMessage(src, dst, msg)
            case MsgType.SERVER.value:
                self.interpretServerRequest(src=src, cmd=dst, options=msg)
            case _:
                self.log(f"Unknown message type received from user `{src}`: `{mtype}`.", logtype='warn')

    def onClientConnect(self, client_socket: socket.socket, client_addr: tuple[str, int]):
        print(f" >>> {client_addr} connected")
        data = client_socket.recv(1024)
        if not data:
            return
        mtype, src, dst, msg = Criptografia.decode_msg(data)
        if mtype == MsgType.CONNCT.value:
            self.interpretMessage(mtype, src, client_socket, client_addr) # FIXME
        else:
            self.interpretMessage(mtype, src, dst, msg)

    def start(self):
        while True:
            (c_socket, c_address) = self.socket.accept()
            self.onClientConnect(c_socket, c_address)

def main():
    serv = Servidor(ADDRESS)
    serv.start()

if __name__ == "__main__":
    main()
