from __future__ import annotations
from crypto.idea import IDEA
from crypto.utils import xor
from crypto.utils import make_key

# CBC mode wrapping a 64‑bit block cipher
class CBC:
    # init to store IDEA object, enc\dec mode bool value, size of each block(fixed 8 bytes), and random IV for encrypt
    def __init__(self, passphrase: str, encrypt: bool):
        self.cipher = IDEA(passphrase, encrypt)
        self.encrypt = encrypt
        self.block = self.cipher.block_size
        self.iv = bytearray(make_key(passphrase, self.block))

    # encrypt or decrypt based on mode, differ in order of XOR
    def process(self, chunk: bytes) -> bytes:
        buf = bytearray(chunk)
        if self.encrypt:
            xor(buf, 0, self.iv)
            self.cipher.crypt_block(buf)
            self.iv[:] = buf
        else: # in decrypt mode we implement as if user already sent iv random key used for encryption
            tmp = buf[:]
            self.cipher.crypt_block(buf)
            xor(buf, 0, self.iv)
            self.iv[:] = tmp
        return bytes(buf)
