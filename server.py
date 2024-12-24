# TODO
#  - criar um servidor para implementar as funcionalidades e requisitos do projeto

import socket
from typing import *

ADDRESS = (socket.gethostname(), 8080)

class Servidor():
    """
    Classe do servidor.
    Baseado em: https://docs.python.org/3/howto/sockets.html
    """
    def __init__(self, address, max_connections = 5):
        self.log_tag = "[SERVER]"
        self.max_connections = max_connections

        self.log("Setting up server...")
        self.socket = self._init_socket(address)
        self.log("Server is up. Waiting for connections...")

    def _init_socket(self, address) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(address)
        s.listen(self.max_connections);
        return s

    def log(self, msg, **args):
        print(self.log_tag, msg, **args)

    def forwardMessage(self, src, dst, msg):
        self.log(f"{src} -> {dst} ({len(msg)} bytes)")
        total_sent = 0
        while total_sent < len(msg):
            sent = self.socket.send(msg[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken.")
            total_sent += sent
        print("Message")

    def onClientConnect(self, client_socket, client_addr):
        print(f" >>> Connection received from {client_addr}")
        data = client_socket.recv(1024)
        if not data:
            return
        self.log(f"Received {len(data)} bytes: {data}")

    def init(self):
        while True:
            (c_socket, c_address) = self.socket.accept()
            self.onClientConnect(c_socket, c_address)

def main():
    serv = Servidor(ADDRESS)
    serv.init()

if __name__ == "__main__":
    main()
