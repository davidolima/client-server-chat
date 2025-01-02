import socket
import warnings
import threading
import struct
from typing import *

from crypto import Criptografia, MsgType

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

    def sendPackage(self, socket: socket.socket, msg: bytes):
        # Enviar msg
        # Baseado em: https://docs.python.org/3/howto/sockets.html
        total_sent = 0
        while total_sent < len(msg):
            sent = socket.send(msg[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken.")
            total_sent += sent

    def sendPackageUsr(self, msg_type: MsgType, src: str , dst: str, msg: str):
        if dst not in self.getOnlineUsers():
            self.sendPackageUsr(MsgType.SERVER, 'server', src, f"Cannot send package. User `{dst}` is not online.")
            return

        enc_msg = Criptografia.encode_msg(msg_type, src, dst, msg)

        client_socket = self.getUserSocket(dst)
        if not client_socket:
            self.log(f"Socket for user `{dst}` is closed. Unable to forward message.", logtype='warn')
            return

        self.sendPackage(client_socket, enc_msg)
        self.log(f"{src} -> {dst} ({len(msg)} bytes): {msg}")

    def sendToAll(self, msg_type: MsgType, src: str, msg: str):
        for usr in self.online_users.keys():
            self.sendPackageUsr(msg_type, src, usr, msg)

    def getUserSocket(self, usr) -> socket.socket:
        return self.online_users[usr][0]

    def getUserAddr(self, usr) -> Tuple[str, int]:
        return self.online_users[usr][1]

    def addUser(self, usr, socket, addr) -> bool:
        ret, msg = False, None
        if usr not in self.online_users:
            self.log(f"User just connected: {usr}@{addr[0]}:{addr[1]}")
            self.online_users[usr] = (socket,addr)
            msg = Criptografia.encode_msg(MsgType.ACCEPT, 'server', usr, f"Bem vindo, {usr}!")
            ret = True
        else:
            msg = Criptografia.encode_msg(MsgType.DENIED, 'server', usr, 'Nome de usuário já existe no servidor')

        self.sendPackage(socket, msg)

        # notify clients
        self.sendToAll(MsgType.SERVER, 'server', f"{usr} se conectou!")
        self.sendToAll(MsgType.USRONL, 'server', str(self.getOnlineUsers()))
        return ret

    def removeUser(self, usr_addr):
        for k, v in self.online_users.items():
            if v[1] == usr_addr:
                self.online_users.pop(k)
                break

        # notify clients
        self.sendToAll(MsgType.USRONL, 'server', str(self.getOnlineUsers()))

    def getOnlineUsers(self):
        return list(self.online_users.keys())

    def interpretServerRequest(self, src:str, cmd: str, options: str):
        #TODO
        #self.sendPackageUsr(MsgType.ACCEPT, src, cmd, str(list(__dict__.keys())))
        return
    
    def sendFileUsr(self, msg_type: MsgType, src: str, dst: str, fnm: str, file_data: bytes):
        if dst not in self.online_users:
            self.sendPackageUsr(MsgType.ERRMSG, 'server', src, f"Cannot forward message; user `{dst}` is not online.")
            return
        
        client_socket = self.getUserSocket(dst)
        if client_socket._closed:
            self.log(f"Socket for user `{dst}` is closed. Unable to forward message.", logtype='warn')
            return

        # Envia informações da transação
        enc_msg = Criptografia.encode_msg(msg_type, src, dst, fnm.replace('\x00', ''))
        client_socket.sendall(enc_msg) 

        # Envia tamanho do arquivo
        fsz = len(file_data)
        client_socket.send(struct.pack('!I', fsz))

        # Envia dados do arquivo
        buffer = 1024
        total_sent = 0
        while total_sent < fsz:
            end = min(total_sent + buffer, fsz)  # Define o tamanho do próximo bloco
            data = file_data[total_sent:end]
            sent = client_socket.send(data)
            if sent == 0:
                raise RuntimeError("Socket connection broken.")
            total_sent += sent
        print(f'File Name Sent: {total_sent} bytes')
    
    def getFileSize(self, sock) -> int:
        received = 0
        chunks = []
        while received < 4:
            data = sock.recv(4 - received)
            received += len(data)
            chunks.append(data)
        fsz = struct.unpack('!I', b''.join(chunks))[0]
        return fsz
    
    def recieveFilePackage(self, src, dst, fnm):
        if dst not in self.online_users:
            self.sendPackageUsr(MsgType.ERRMSG, 'server', src, f"Cannot forward message; user `{dst}` is not online.")
            return
        
        src_socket = self.getUserSocket(src)
        fsz = self.getFileSize(src_socket)

        # Recebe o arquivo
        chunks = b''
        total_received = 0
        while total_received < fsz:
            data = src_socket.recv(1024)
            if not data:
                break
            chunks += data
            total_received += len(data)
        
        self.sendPackageUsr(MsgType.ACCEPT, 'server', src, 'OK')
        self.sendFileUsr(MsgType.FWDFL, src, dst, fnm, chunks)

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

            case  MsgType.FWDFL.value:
                assert(type(src) == str and type(dst) == str and type(msg) == str)
                self.recieveFilePackage(src, dst, fnm = msg)               

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
                elif mtype == MsgType.FWDFL.value:
                    #Receber o nome do arquivo e enviar para o dst
                    self.interpretMessage(mtype, src, dst, msg)
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

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=socket.gethostname(), type=str)
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()

    serv = Servidor((args.host, args.port))
    serv.startWithTerminal()
