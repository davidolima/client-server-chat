# TODO
# - criar codigo para criptografar as conexoes
# - voce pode usar criptografia simetrica ou assimetrica (AES ou RSA)

from typing import *
import struct

from enum import Enum
import warnings

class MsgType(Enum):
    ERRMSG = 0 # Error
    ACCEPT = 1 # Accept
    DENIED = 2 # Denied
    FWDMSG = 3 # Forward Message
    CONNCT = 4 # Connection
    DISCNT = 5 # Disconnect
    SERVER = 6 # Requisição para o servidor
    FWDFL  = 7 # Forward File
    USRONL = 8 # Usuários online
    CKLG = 9 # Checagem de login

class Criptografia:
    @staticmethod
    def encode_msg(msg_type: MsgType, src: str, dst: str, msg: str, encoding='utf-8') -> bytes:
        if len(msg) > 956:
            # TODO: Tamanho dinâmico de mensagens
            warnings.warn("Mensagem muito grande para ser enviada.")
            return b''
        b_src = bytes(src, encoding)
        b_dst = bytes(dst, encoding)
        b_msg = bytes(msg, encoding)
        return struct.pack(
            "@bb32sb32sb956s",
            msg_type.value,
            len(src), b_src,
            len(dst), b_dst,
            len(msg), b_msg
        )
        
    @staticmethod
    def decode_msg(data: bytes, encoding='utf-8') -> tuple[MsgType, str, str, str]:
        """
        Decodifica uma mensagem em bytes:
         - [1] Tipo da mensagem (Ver MsgType)
         - [2] Tamanho do nome de usuário de origem
         - [3-34] Nome de usuário de origem
         - [35] Tamanho do nome de usuário de destino
         - [36-67] Nome de usuário de destino
         - [68-1024] Mensagem
        """
        if len(data) < 1024:
            while len(data) < 1024:
                data += b'\00'
        decoded_msg = struct.unpack("@bb32sb32sb956s", data)

        mtype = decoded_msg[0]
        src = decoded_msg[2][:decoded_msg[1]].decode(encoding)
        dst = decoded_msg[4][:decoded_msg[3]].decode(encoding)
        msg = decoded_msg[6][:decoded_msg[5]+1].decode(encoding)

        return mtype, src, dst, msg
