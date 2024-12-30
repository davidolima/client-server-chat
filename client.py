# TODO
# [X] cada cliente se comunica com o servidor, que gerenciara a comunicacao entre clientes
# [  ] cada cliente deve se cadastrar junto ao servidor como um usuario
# [X] cada cliente deve poder se comunicar com outro cliente usando o nome de usuario (semelhante ao que ocorre no WhatsApp atraves do numero de telefone)
# [  ] (OPCIONAL) clientes podem se juntar a grupos multicast (semelhante ao que ocorre no whatsapp)

import socket
import warnings
from typing import *
from time import sleep

import threading

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

    def isConnected(self) -> bool:
        return (self.socket is not None)

    def connect(self, host: str, port: int) -> None:
        if self.isConnected():
            warnings.warn("Already connected!")
            return

        self.host, self.port = host, port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect( (self.host, self.port) )
        self.authenticate()

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

    def sendMessage(self, dst, msg: str) -> None:
        self.sendPackage(MsgType.FWDMSG, dst, msg)
        self.registerMessage(f"{self.username}: {msg}")

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

    def registerMessage(self, msg):
        if self.dst in self.msg_history.keys():
            self.msg_history[self.dst].append(msg)
        else:
            self.msg_history[self.dst] = [msg]

    def getMsgHistoryWithUsr(self, usr):
        if usr not in self.msg_history.keys():
            self.msg_history[usr] = []
        return self.msg_history[usr]

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

    def interpretMessage(self, mtype, src, dst, msg) -> bool:
        interrupt = False
        match(mtype):
            case MsgType.FWDMSG.value:
                self.registerMessage(f"{src}: {msg}")
            case MsgType.SERVER.value:
                self.registerMessage(f"[SERVER] {msg}")
            case MsgType.ERRMSG.value:
                self.registerMessage(f"[ERROR] The server reported an error: {msg}")
                interrupt = True
            case MsgType.DISCNT.value:
                self.registerMessage(f"[SERVER] Disconnected from server: {msg}")
                interrupt = True
            case _:
                pass
        return interrupt

    def start_receive_loop(self):
        def receive_messages():
            while self.isConnected():
                try:
                    msg_type, src, dst, msg = self.receivePackage()
                    interrupt = self.interpretMessage(msg_type, src, dst, msg)
                    if interrupt:
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
                usr = input("Escolha um usuário para conversar: ")
                if usr.startswith('\\'):
                    self.intepretCommand(usr)
                self.dst = usr
                self.getMsgHistoryWithUsr(self.dst) # iniciar histórico de conversa com dst

            else:
                msg = input(f"({self.username} -> {self.dst}) > ")
                print('\033[1A' + '\033[K', end='')
                self.intepretCommand(msg)

if __name__ == "__main__":
    c = Cliente()
    c.start(socket.gethostname(), 8080)
