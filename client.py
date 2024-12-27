# TODO
#  - conexao com o servidor para implementar as funcionalidades e requisitos do projeto

# - cada cliente se comunica com o servidor, que gerenciara a comunicacao entre clientes
# - cada cliente deve se cadastrar junto ao servidor como um usuario
# - cada cliente deve poder se comunicar com outro cliente usando o nome de usuario (semelhante ao que ocorre no WhatsApp atraves do numero de telefone)
# - (OPCIONAL) clientes podem se juntar a grupos multicast (semelhante ao que ocorre no whatsapp)

import socket
import struct
from typing import *
from threading import Thread

MSGLEN = 2048

class Cliente:
    """
    Classe cliente.
    Baseado em: https://docs.python.org/3/howto/sockets.html
    """
    

    def __init__(self, login):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((socket.gethostname(), 8080))
        self.login = login

    def disconnect(self):
        self.socket.shutdown(0)
        self.socket.close()

    def receive_msg(self):
        while True:
            server_msg = self.socket.recv(1024).decode()
            if not server_msg.strip():
                self.disconnect()
            print("DESCONECTADO")

    def send_msg(self):
        dest = input("Enviar para: ")
        while True:
            client_msg = input("")
            final_msg = f'{self.login}: {client_msg}'
            msg_codificada = Cliente.encode_msg(dest, final_msg)       

            self.socket.send(msg_codificada)

            """
            totalsent = 0
            lenMsg = len(msg)
            while totalsent < lenMsg:
                sent = self.socket.send(msg[totalsent:])
                if sent == 0:
                    raise RuntimeError("socket connection broken")
                totalsent = totalsent + sent
            """
    
    def server_comunication(self):
        self.socket.send(self.login.encode())
        Thread(target = self.receive_msg).start()
        self.send_msg()
    
    @staticmethod
    def encode_msg(dst: str, msg: str, encoding='utf-8') -> bytes:
        bdst = bytes(dst, encoding)
        bmsg = bytes(msg, encoding)
        return struct.pack(
            "@b64sb957s",
            len(dst), bdst,
            len(msg), bmsg
        )

    @staticmethod
    def decode_msg(data: bytes, encoding='utf-8') -> tuple[str, str]:
        """
        Decodifica uma mensagem em bytes:
         - [1] Tamanho do nome de usuário de origem
         - [2-64] Nome de usuário de origem
         - [64-1024] Mensagem
        """
        decoded_msg = struct.unpack("@b64sb957s", data)
        dst = decoded_msg[1][:decoded_msg[0]].decode(encoding)
        msg = decoded_msg[3][:decoded_msg[2]].decode(encoding)
        return dst, msg
    
def main():
    print("Bem vindo! Para acessar o chat, digite:")
    login = input("Login -> ") # Aqui provalmente terá uma validação
    
    client = Cliente(login)
    client.server_comunication()

if __name__ == "__main__":
    main()