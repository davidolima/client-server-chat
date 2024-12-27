# TODO
#  - conexao com o servidor para implementar as funcionalidades e requisitos do projeto

# - cada cliente se comunica com o servidor, que gerenciara a comunicacao entre clientes
# - cada cliente deve se cadastrar junto ao servidor como um usuario
# - cada cliente deve poder se comunicar com outro cliente usando o nome de usuario (semelhante ao que ocorre no WhatsApp atraves do numero de telefone)
# - (OPCIONAL) clientes podem se juntar a grupos multicast (semelhante ao que ocorre no whatsapp)

import socket
import warnings
from typing import *

import threading

from crypto import Criptografia, MsgType

MSGLEN = 1024

class Cliente:
    """
    Classe cliente.
    """

    def __init__(self):
        self.socket = None
        self.username = "user"
        self.dst = None
        self.online_users = []

    def isConnected(self) -> bool:
        return (self.socket is not None)

    def connect(self, host: str, port: int) -> None:
        if self.isConnected():
            warnings.warn("Already connected!")
            return

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.authenticate()

    def disconnect(self) -> None:
        if not self.isConnected():
            warnings.warn("Attempted to disconnect without a connection.")
            return
        assert (self.socket is not None) # NOTE: Just so LSP works properly

        print("Disconnecting...")
        self.socket.shutdown(0)
        self.socket.close()
        print("Disconnected!")

    def sendMessage(self, dst, msg: str) -> None:
        self.sendPackage(MsgType.FWDMSG, dst, msg)
        print(f"{self.username}: {msg}")

    def sendPackage(self, msg_type: MsgType, dst: str, msg: str):
        """
        Baseado em: https://docs.python.org/3/howto/sockets.html
        """
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return
        assert(self.socket is not None)  # NOTE: Just so LSP works properly

        enc_msg = Criptografia.encode_msg(msg_type, self.username, dst, msg)
        self.socket.sendall(enc_msg)

        print(f"Sent {len(enc_msg)} bytes: {MsgType.FWDMSG} {self.username} {dst} {msg}")

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

    def authenticate(self) -> None:
        if not self.isConnected():
            warnings.warn("Not connected to server.")
            return
        assert(self.socket is not None) # NOTE: Just so LSP works properly

        print("Por favor, autentique-se:")
        username = input("Usuário: ")
        self.username = username

        addr, port = self.socket.getsockname()
        self.sendPackage(MsgType.CONNCT, str(addr), str(port))

    def serverRequest(self, request, options):
        self.sendPackage(MsgType.SERVER, request, options)
        return msg

    def intepretCommand(self, cmd: str) -> None:
        if cmd.startswith('\\'): # Comandos
            if cmd == '\\q': # Sair
                if self.dst is not None: # De conversas
                    self.dst = None
                else: # Do programa (desconectar)
                    self.disconnect()
                    quit()
        else:
            self.sendMessage(self.dst, cmd)

    def interpretMessage(self, mtype, src, dst, msg):
        match(mtype):
            case MsgType.FWDMSG.value:
                print(f"{src}: {msg}")
            case MsgType.SERVER.value:
                print(f"[SERVER] {msg}")
            case _:
                pass

    def start_receive_loop(self):
        def receive_messages():
            while self.isConnected():
                try:
                    msg_type, src, dst, msg = self.receivePackage()
                    self.interpretMessage(msg_type, src, dst, msg)
                    if msg_type == MsgType.ERRMSG:
                        print(f"[ERROR] The server reported an error: {msg}")
                        break
                except Exception as e:
                    print(f"Error receiving message: {e}")
                    break
            self.disconnect()

        thread = threading.Thread(target=receive_messages, daemon=True)
        thread.start()

    def start(self, server_addr, server_port):
        self.connect(server_addr, server_port)
        self.start_receive_loop()
        while True:
            if (self.dst is None):
                #if not self.online_users:
                #    self.online_users = self.serverRequest('getOnlineUsers', '')
                usr = input(f"Escolha um usuário: ")
                if usr.startswith('\\'):
                    self.intepretCommand(usr)
                self.dst = usr
            else:
                msg = input(f"[{self.dst}] > ")
                print('\033[1A' + '\033[K', end='')
                self.intepretCommand(msg)

if __name__ == "__main__":
    c = Cliente()
    c.start(socket.gethostname(), 8080)
