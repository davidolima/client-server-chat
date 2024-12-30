import socket
import warnings
import threading
from typing import *

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

    def log(self, msg, logtype: Literal['server', 'info', 'warn'] = 'server', **args):
        prefix = "[SERVER]"

        if logtype == 'warn':
            prefix = "[SERVER WARNING]"
        elif logtype == 'info':
            prefix = "[INFO]"

        print(prefix, msg, **args)

    def forwardMessage(self, src, dst, msg):
        if dst not in self.online_users:
            self.sendPackageUsr(MsgType.SERVER, 'server', src, f"Cannot forward message. User `{dst}` is not online.")
            return

        #self.log(f"Forwarding message: src: {src} dst: {dst} msg: {msg}")
        self.sendPackageUsr(MsgType.ACCEPT, 'server', src, 'OK')
        self.sendPackageUsr(MsgType.FWDMSG, src, dst, msg)

    def sendPackageUsr(self, msg_type: MsgType, src: str , dst: str, msg: str):
        if dst not in self.getOnlineUsers():
            self.sendPackageUsr(MsgType.SERVER, 'server', src, f"Cannot send package. User `{dst}` is not online.")
            return

        enc_msg = Criptografia.encode_msg(msg_type, src, dst, msg)

        client_socket = self.getUserSocket(dst)
        if client_socket._closed:
            self.log(f"Socket for user `{dst}` is closed. Unable to forward message.", logtype='warn')
            return

        # Enviar msg
        # Baseado em: https://docs.python.org/3/howto/sockets.html
        total_sent = 0
        while total_sent < len(msg):
            sent = client_socket.send(enc_msg[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken.")
            total_sent += sent
        self.log(f"{src} -> {dst} ({len(msg)} bytes): {msg}")

    def sendToAll(self, msg_type: MsgType, src: str, msg: str):
        for usr in self.online_users.keys():
            self.sendPackageUsr(msg_type, src, usr, msg)

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

    def removeUser(self, usr_addr):
        for k, v in self.online_users.items():
            if v[1] == usr_addr:
                self.online_users.pop(k)
                break

    def getOnlineUsers(self):
        return list(self.online_users.keys())

    def interpretServerRequest(self, src:str, cmd: str, options: str):
        #TODO
        #self.sendPackageUsr(MsgType.ACCEPT, src, cmd, str(list(__dict__.keys())))
        return

    def interpretMessage(self, mtype: MsgType, src: str, dst: str | socket.socket, msg: str | Tuple[str, int]):
        match (mtype):
            case MsgType.CONNCT.value:
                assert(type(src) == str and\
                       type(dst) == socket.socket and\
                       type(msg) == tuple)
                self.addUser(src, socket=dst, addr=msg)

            case MsgType.DISCNT.value:
                self.removeUser(src)

            case MsgType.FWDMSG.value:
                assert(type(src) == str and type(dst) == str)
                self.forwardMessage(src, dst, msg)

            case MsgType.SERVER.value:
                assert(type(src) == str and type(dst) == str and type(msg) == str)
                self.interpretServerRequest(src=src, cmd=dst, options=msg)

            case _:
                self.log(f"Unknown message type received from user `{src}`: `{mtype}`.", logtype='warn')

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

            case _:
                self.log(f"Comando não reconhecido: `{cmd}`", logtype='info')

    def onClientConnect(self, client_socket: socket.socket, client_addr: tuple[str, int]):
        print(f" >>> {client_addr} connected.")

        try:
            while True:
                data = client_socket.recv(1024)
                if not data: return

                mtype, src, dst, msg = Criptografia.decode_msg(data)
                if mtype == MsgType.CONNCT.value:
                    self.interpretMessage(mtype, src, client_socket, client_addr) # FIXME
                elif mtype == MsgType.DISCNT.value:
                    break
                else:
                    self.interpretMessage(mtype, src, dst, msg)

        except Exception as e:
            self.log(f"Error handling client {client_addr}: {e}", logtype="warn")

        finally:
            client_socket.close()
            self.removeUser(client_addr)
            self.log(f" <<< {client_addr} disconnected.")
            self.log(f"Online users: {self.getOnlineUsers()}")


    def start(self):
        while True:
            (c_socket, c_address) = self.socket.accept()
            #self.onClientConnect(c_socket, c_address)
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

def main():
    serv = Servidor(ADDRESS)
    serv.startWithTerminal()

if __name__ == "__main__":
    main()
