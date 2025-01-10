# TODO
# - criar codigo para criptografar as conexoes
# - voce pode usar criptografia simetrica ou assimetrica (AES ou RSA)

from typing import *
import struct

import rsa

from enum import Enum
import warnings

from rsa.pkcs1 import DecryptionError

PKG_SIZE = 2048
USERNAME_SIZE = 32
HEADER_SIZE = 1 + 1 + 2*USERNAME_SIZE + 1 + 2
MSG_SIZE = PKG_SIZE - HEADER_SIZE - 1
PKG_STRUCT = f"B B {USERNAME_SIZE}s B {USERNAME_SIZE}s H {MSG_SIZE}s"
RSA_KEY_SIZE = 1024
PKG_CHUNK_SIZE = (RSA_KEY_SIZE +7)//8 - 11
ENCODING = 'utf-8'

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
    def unpackMessage(data: bytes, privkey: rsa.PrivateKey | None = None, encoding=ENCODING) -> tuple[MsgType, str, str, str]:
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
        while len(data) < PKG_SIZE:
            data += b'\00'

        decoded_msg = struct.unpack(PKG_STRUCT, data)

        mtype = decoded_msg[0]
        src = decoded_msg[2][:decoded_msg[1]].decode(encoding)
        dst = decoded_msg[4][:decoded_msg[3]].decode(encoding)
        msg = decoded_msg[6][:decoded_msg[5]]

        if privkey and len(msg) > 0:
            try:
                msg = Criptografia.decrypt_chunked(msg, privkey)
            except DecryptionError:
                pass # Assumir que a imagem não está criptografada

        try:
            return mtype, src, dst, msg.decode(ENCODING)
        except:
            return mtype, src, dst, str(msg)

    @staticmethod
    def packMessage(msg_type: MsgType, src: str | bytes, dst: str | bytes, msg: str | bytes, pubkey: rsa.PublicKey | None = None, encoding=ENCODING):
        if len(msg) > MSG_SIZE:
            # TODO: Tamanho dinâmico de mensagens
            warnings.warn("Mensagem muito grande para ser enviada.")
            return b''

        b_src = src if (type(src) == bytes) else bytes(src, encoding)
        b_dst = dst if (type(dst) == bytes) else bytes(dst, encoding)
        b_msg = msg if (type(msg) == bytes) else bytes(msg, encoding)

        if pubkey and Criptografia.can_encrypt_with_rsa(b_msg, pubkey):
            b_msg = Criptografia.encrypt_chunked(b_msg, pubkey)

        assert(len(b_src) <= USERNAME_SIZE and len(b_dst) <= USERNAME_SIZE and len(b_msg) <= MSG_SIZE)
        return struct.pack(
            PKG_STRUCT,
            msg_type.value,
            len(src), b_src,
            len(dst), b_dst,
            len(msg), b_msg
        )

    @staticmethod
    def encrypt_chunked(msg: bytes, pubkey: rsa.PublicKey) -> bytes:
        """Encrypts a message by breaking it into chunks and encrypting each chunk"""
        chunks = [msg[i:i+PKG_CHUNK_SIZE] for i in range(0, len(msg), PKG_CHUNK_SIZE)]
        encrypted_chunks = [rsa.encrypt(x, pubkey) for x in chunks]
        return b''.join(encrypted_chunks)

    @staticmethod
    def decrypt_chunked(data: bytes, privkey: rsa.PrivateKey) -> bytes:
        """Decrypt a message that was encrypted in chunks"""
        enc_chunks = [data[i:i+PKG_CHUNK_SIZE+11] for i in range(0, len(data), PKG_CHUNK_SIZE+11)]
        dec_chunks = [rsa.decrypt(x, privkey) for x in enc_chunks]
        return b''.join(dec_chunks)

    @staticmethod
    def generate_rsa_keys() -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
        pub, priv = rsa.newkeys(RSA_KEY_SIZE)
        return (pub, priv)

    @staticmethod
    def pubkey_from_str(s: str) -> rsa.PublicKey:
        """
        takes in strings (1234, 5678)
        and returns a public key with
        n=1234 and e=5678.
        """
        assert s is not None
        names_and_keys = [x.split(',PublicKey') for x in s.replace(' ', '').replace('\'','')[2:-2].split("),(")]
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
