from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import TAG_LEN


def aes_ecb_decrypt_block(key: bytes, block: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(block) + decryptor.finalize()


def nonce(counter: int) -> bytes:
    return counter.to_bytes(12, "little")


class AesGcmStream:
    def __init__(self, key: bytes) -> None:
        self.aesgcm = AESGCM(key)
        self.counter = 0

    def decrypt(self, data: bytes) -> bytes:
        out = self.aesgcm.decrypt(nonce(self.counter), data, None)
        self.counter += 1
        return out

    def encrypt(self, data: bytes) -> bytes:
        out = self.aesgcm.encrypt(nonce(self.counter), data, None)
        self.counter += 1
        return out


def encrypted_len(plain_len: int) -> int:
    return plain_len + TAG_LEN


def pack_length(length: int) -> bytes:
    return struct.pack("!H", length)

def unpack_length(data: bytes) -> int:
    return struct.unpack("!H", data)[0]

