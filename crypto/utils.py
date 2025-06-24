# Derive a fixed 16 bit length key from an arbitrary pass‑phrase Simple XOR folding
def make_key(passphrase: str, length: int = 16) -> bytes:
    key = bytearray(length)
    for i, ch in enumerate(passphrase.encode()):
        key[i % length] ^= ch
    return bytes(key)

# Xor a block of bytes with a given IV
def xor(block: bytearray, offset: int, iv: bytes) -> None:
    for i in range(len(iv)):
        block[offset + i] ^= iv[i]

# Combine a two 8 bit values into a single 16-bit integer
def concat16(b1: int, b2: int) -> int:
    return ((b1 & 0xFF) << 8) | (b2 & 0xFF)
