# TODO
#  - criar um servidor para implementar as funcionalidades e requisitos do projeto

import socket
from typing import *
from threading import Thread
from client import Cliente

ADDRESS = (socket.gethostname(), 8080)

class Servidor():
    Clients = []
    
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
        print(msg)

    def onClientConnect(self, client_socket, client_addr):
        self.log(f" >>> Connection received from {client_addr}")

        client_name = client_socket.recv(1024).decode()
        client = {'name': client_name, 'socket': client_socket}
        Servidor.Clients.append(client)

        Thread(target = self.handle_new_client, args=(client,)).start()

    def handle_new_client(self, client):
        client_name = client['name']
        client_socket = client['socket']
        
        while True:
            client_msg = client_socket.recv(1024)
            (dst, msg) = Cliente.decode_msg(client_msg)

            if msg.strip() == client_name + ": bye" or not msg.strip():
                self.log(f'Conexão com {client_name} encerrada')
                Servidor.Clients.remove(client)
                client_socket.close()
                break
            else:
                self.forwardMessage(client_name, dst, msg)


    def init(self):
        while True:
            (c_socket, c_address) = self.socket.accept()
            self.onClientConnect(c_socket, c_address)

def main():
    serv = Servidor(ADDRESS)
    serv.init()

if __name__ == "__main__":
    main()
