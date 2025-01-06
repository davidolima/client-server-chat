# TODO
# - criar codigo para criptografar as conexoes
# - voce pode usar criptografia simetrica ou assimetrica (AES ou RSA)

from typing import *
import struct

import rsa

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
    CKLG   = 9 # Checagem de login
    RGUSR  = 10 # Registro de usuário

class Criptografia:
    @staticmethod
    def encode_msg(msg_type: MsgType, src: str, dst: str, msg: str, pubkey: rsa.PublicKey | None = None, encoding='utf-8') -> bytes:
        if len(msg) > 1978:
            # TODO: Tamanho dinâmico de mensagens
            warnings.warn("Mensagem muito grande para ser enviada.")
            return b''

        if pubkey and not Criptografia.can_encrypt_with_rsa(msg, pubkey):
            raise ValueError("Message too large to encrypt with the given RSA key.")

        b_src = bytes(src, encoding)
        b_dst = bytes(dst, encoding)
        b_msg = bytes(msg, encoding)

        print(f"msg_type={msg_type.value}, len(src)={len(b_src)}, len(dst)={len(b_dst)}, len(msg)={len(b_msg)}")
        assert(len(b_src) <= 32 and len(b_dst) <= 32 and len(b_msg) <= 1978)

        return struct.pack(
            "B B 32s B 32s H 1978s",
            msg_type.value,
            len(src), b_src,
            len(dst), b_dst,
            len(msg), rsa.encrypt(b_msg, pubkey) if pubkey else b_msg
        )
        
    @staticmethod
    def decode_msg(data: bytes, priv_key: rsa.PrivateKey | None = None, encoding='utf-8') -> tuple[MsgType, str, str, str]:
        """
        Decodifica uma mensagem em bytes:
         - [1] Tipo da mensagem (Ver MsgType)
         - [2] Tamanho do nome de usuário de origem
         - [3-34] Nome de usuário de origem
         - [35] Tamanho do nome de usuário de destino
         - [36-67] Nome de usuário de destino
         - [68] Tamanho da mensagem
         - [69-2048] Mensagem
        """
        if len(data) < 2048:
            while len(data) < 2048:
                data += b'\00'

        decoded_msg = struct.unpack("B B 32s B 32s H 1978", data)

        mtype = decoded_msg[0]
        src = decoded_msg[2][:decoded_msg[1]].decode(encoding)
        dst = decoded_msg[4][:decoded_msg[3]].decode(encoding)

        msg = decoded_msg[6][:decoded_msg[5]]
        if priv_key:
            msg = rsa.decrypt(msg, priv_key)
        msg = msg.decode(encoding)

        return mtype, src, dst, msg

    @staticmethod
    def generate_rsa_keys() -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
        pub, priv = rsa.newkeys(1024)
        return (pub, priv)

    @staticmethod
    def pubkey_from_str(s: str) -> rsa.PublicKey:
        """
        takes in strings (1234, 5678)
        and returns a public key with
        n=1234 and e=5678.
        """
        assert s is not None
        n, e = map(int, s[1:-1].strip().split(','))
        return rsa.PublicKey(n=n, e=e)

    @staticmethod
    def str_from_pubkey(p: rsa.PublicKey) -> str:
        """
        Takes in public key and returns a string
        of shape (n,e)
        """
        return str(p).replace("PublicKey", '')

    @staticmethod
    def can_encrypt_with_rsa(message: bytes, pubkey: rsa.PublicKey) -> bool:
        key_size = rsa.common.byte_size(pubkey.n)
        max_message_size = key_size - 11  # 11 bytes for PKCS#1 padding
        return len(message) <= max_message_size


if __name__ == '__main__':
    pass
