# TODO
#  - conexao com o servidor para implementar as funcionalidades e requisitos do projeto

# - cada cliente se comunica com o servidor, que gerenciara a comunicacao entre clientes
# - cada cliente deve se cadastrar junto ao servidor como um usuario
# - cada cliente deve poder se comunicar com outro cliente usando o nome de usuario (semelhante ao que ocorre no WhatsApp atraves do numero de telefone)
# - (OPCIONAL) clientes podem se juntar a grupos multicast (semelhante ao que ocorre no whatsapp)

import socket
import struct
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

    @staticmethod
    def encode_msg(src: str, dst: str, msg: str, encoding='utf-8') -> bytes:
        bsrc = bytes(src, encoding)
        bdst = bytes(dst, encoding)
        bmsg = bytes(msg, encoding)
        return struct.pack(
            "@b32sb32sb957s",
            len(src), bsrc,
            len(dst), bdst,
            len(msg), bmsg
        )

    @staticmethod
    def decode_msg(data: bytes, encoding='utf-8') -> tuple[str, str, str]:
        """
        Decodifica uma mensagem em bytes:
         - [1] Tamanho do nome de usuário de origem
         - [2-33] Nome de usuário de origem
         - [34] Tamanho do nome de usuário de destino
         - [35-66] Nome de usuário de destino
         - [67-1024] Mensagem
        """
        decoded_msg = struct.unpack("@b32sb32sb957s", data)
        src = decoded_msg[1][:decoded_msg[0]].decode(encoding)
        dst = decoded_msg[3][:decoded_msg[2]].decode(encoding)
        msg = decoded_msg[5][:decoded_msg[4]].decode(encoding)
        return src, dst, msg

if __name__ == "__main__":
    c = Cliente()
    c.connect(socket.gethostname(), 8080)

    msg_pkt = Cliente.encode_msg("david", "leobino", "olá!")
    print(msg_pkt, Cliente.decode_msg(msg_pkt))
    c.enviar(msg_pkt)
