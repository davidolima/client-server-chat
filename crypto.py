from typing import *
import struct

import rsa

from enum import Enum
import warnings

from rsa.pkcs1 import DecryptionError

PKG_SIZE = 2048
USERNAME_SIZE = 32
HEADER_SIZE = 1 + 1 + 2*USERNAME_SIZE + 1 + 2
MSG_SIZE = PKG_SIZE - HEADER_SIZE
PKG_STRUCT = f">B B {USERNAME_SIZE}s B {USERNAME_SIZE}s H {MSG_SIZE}s"
RSA_KEY_SIZE = 1024
PKG_CHUNK_SIZE = (RSA_KEY_SIZE+7)//8 - 11
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
    def unpackMessage(data: bytes, privkey: rsa.PrivateKey | None = None, encoding=ENCODING) -> tuple[MsgType, str, str, str | bytes]:
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
        while len(data) < PKG_SIZE-1:
            data += b'\0'

        decoded_msg = struct.unpack(PKG_STRUCT, data)

        mtype = MsgType(decoded_msg[0])
        src = decoded_msg[2].decode(encoding)[:int(decoded_msg[1])]
        dst = decoded_msg[4].decode(encoding)[:int(decoded_msg[3])]
        msg = decoded_msg[6][:int(decoded_msg[5])]

        if privkey and len(msg) > 0:
            msg = Criptografia.decrypt_chunked(msg, privkey)

        try:
            return mtype, src, dst, msg.decode(ENCODING)
        except:
            return mtype, src, dst, (msg if type(msg) == bytes else str(msg))

    @staticmethod
    def packMessage(msg_type: MsgType, src: str | bytes, dst: str | bytes, msg: str | bytes, pubkey: rsa.PublicKey | None = None, encoding=ENCODING):
        if len(msg) > PKG_SIZE:
            # TODO: Tamanho dinâmico de mensagens
            warnings.warn("Mensagem muito grande para ser enviada.")
            return b''

        b_src = src if (type(src) == bytes) else src.encode(encoding)
        b_dst = dst if (type(dst) == bytes) else dst.encode(encoding)
        b_msg = msg if (type(msg) == bytes) else msg.encode(encoding)

        if pubkey:
            b_msg = Criptografia.encrypt_chunked(b_msg, pubkey)

        return struct.pack(
            PKG_STRUCT,
            msg_type.value,
            len(b_src), b_src,
            len(b_dst), b_dst,
            len(b_msg), b_msg
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
        pub, priv = rsa.newkeys(RSA_KEY_SIZE, accurate=True, poolsize=2)
        return (pub, priv)

    @staticmethod
    def pubkey_from_str(s: str) -> rsa.PublicKey:
        """
        takes in strings (1234, 5678)
        and returns a public key with
        n=1234 and e=5678.
        """
        assert s is not None
        s = s.replace('PublicKey', '').strip().strip('()')
        n, e = map(int, s.split(','))
        return rsa.PublicKey(n=n, e=e)

    @staticmethod
    def str_from_pubkey(p: rsa.PublicKey) -> str:
        """
        Takes in public key and returns a string
        of shape (n,e)
        """
        assert p is not None
        return str(p).replace("PublicKey", '')

if __name__ == '__main__':
    from string import printable
    import random
    pub, priv = rsa.newkeys(1024)

    for i in range(2048):
        msg = ''.join([random.choice(printable) for _ in range(i)]).encode('utf-8')
        print(f"Test {i}/2048: {msg}")
        enc_msg = Criptografia.encrypt_chunked(msg, pub)
        dec_msg = Criptografia.decrypt_chunked(enc_msg, priv)
        if msg == dec_msg:
            continue
        else:
            print("Encryption failed")
            print("Message:", msg)
            print("Encrypted:", enc_msg)
            print("Decrypted:", dec_msg)
            quit(1)

    print("Encryption passed all tests.")
