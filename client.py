# TODO
#  - conexao com o servidor para implementar as funcionalidades e requisitos do projeto

# - cada cliente se comunica com o servidor, que gerenciara a comunicacao entre clientes
# - cada cliente deve se cadastrar junto ao servidor como um usuario
# - cada cliente deve poder se comunicar com outro cliente usando o nome de usuario (semelhante ao que ocorre no WhatsApp atraves do numero de telefone)
# - (OPCIONAL) clientes podem se juntar a grupos multicast (semelhante ao que ocorre no whatsapp)

import socket
from typing import *

MSGLEN = 2048

class Cliente:
    """
    Classe cliente.
    Baseado em: https://docs.python.org/3/howto/sockets.html
    """

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False

    def connect(self, host, port):
        if not self.connected:
            self.socket.connect((host, port))
            self.connected = True
        return self.connected

    def disconnect(self):
        self.socket.shutdown(0)
        self.socket.close()

    def enviar(self, msg):
        self.socket.sendall(msg)
        data = self.socket.recv(1024)
        print(f"[Client] Server response: {data}")

    def receber(self):
        chunks = []
        bytes_recd = 0
        while bytes_recd < MSGLEN:
            chunk = self.socket.recv(min(MSGLEN - bytes_recd, 2048))
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        return b''.join(chunks)

if __name__ == "__main__":
    c = Cliente()
    c.connect(socket.gethostname(), 8080)
    c.enviar(b"Teste")
