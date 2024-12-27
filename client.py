# TODO
#  - conexao com o servidor para implementar as funcionalidades e requisitos do projeto

# - cada cliente se comunica com o servidor, que gerenciara a comunicacao entre clientes
# - cada cliente deve se cadastrar junto ao servidor como um usuario
# - cada cliente deve poder se comunicar com outro cliente usando o nome de usuario (semelhante ao que ocorre no WhatsApp atraves do numero de telefone)
# - (OPCIONAL) clientes podem se juntar a grupos multicast (semelhante ao que ocorre no whatsapp)

import socket
import warnings
from typing import *

from crypto import Criptografia, MsgType

MSGLEN = 2048

class Cliente:
    """
    Classe cliente.
    Baseado em: https://docs.python.org/3/howto/sockets.html
    """

    def __init__(self):
        self.socket = None
        self.username = "user"
        self.dst = None
        self.online_users = []

    def isConnected(self) -> bool:
        return not (self.socket is None)

    def connect(self, host: str, port: int) -> None:
        if not self.isConnected():
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.authenticate()
            return
        warnings.warn("Already connected!")

    def disconnect(self) -> None:
        print("Disconnecting...")
        if self.isConnected():
            self.socket.shutdown(0)
            self.socket.close()
            print("Disconnected!")
            return
        warnings.warn("Attempted to disconnect without a connection.")

    def sendMessage(self, dst, msg: str) -> None:
        self.sendPackage(MsgType.FWDMSG, dst, msg)

    def sendPackage(self, msg_type: MsgType, dst: str, msg: str):
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return

        enc_msg = Criptografia.encode_msg(msg_type, self.username, dst, msg)
        self.socket.sendall(enc_msg)

    def receivePackage(self) -> tuple[MsgType, str,str,str]:
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return (MsgType.ERRMSG, '', '', '')

        data = self.socket.recv(1024)
        if not data:
            warnings.warn("No data received.")
       # print(len(data), data)
        msg_type, src, dst, msg = Criptografia.decode_msg(data)
        return msg_type, src, dst, msg

    def authenticate(self) -> None:
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return

        print("Por favor, autentique-se:")
        username = input("Usuário: ")
        self.username = username

        addr, port = self.socket.getsockname()
        self.sendPackage(MsgType.CONNCT, str(addr), str(port))

        _, _, _, msg = self.receivePackage()
        print(f"[Server] {msg}")

    def serverRequest(self, request, options):
        self.sendPackage(MsgType.SERVER, request, options)
        _, _, _, msg = self.receivePackage()
        return msg

    def intepretCommand(self, cmd: str) -> None:
        if cmd.startswith('\\'): # Comandos
            if cmd == '\\q': # Sair
                if self.dst is not None: # De conversas
                    self.dst = None
                else: # Do programa (desconectar)
                    self.disconnect()
        else:
            self.sendMessage(self.dst, cmd)

    def interpretMessage(self, mtype, src, dst, msg):
        match(mtype):
            case MsgType.FWDMSG:
                print(f" {src}: {msg}")
            case _:
                pass

    def start(self, server_addr, server_port):
        self.connect(server_addr, server_port)
        while True:
            if (self.dst is None):
                #if not self.online_users:
                #    self.online_users = self.serverRequest('getOnlineUsers', '')
                usr = input(f"Escolha um usuário: ")
                self.dst = usr
            else:
                msg = input(f"[{self.dst}] > ")
                self.intepretCommand(msg)

if __name__ == "__main__":
    c = Cliente()
    c.start(socket.gethostname(), 8080)
