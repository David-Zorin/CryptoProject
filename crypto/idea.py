from __future__ import annotations

from crypto.utils import concat16, make_key

# IDEA cipher (8 rounds + half round of output transformation , 64‑bit blocks)
class IDEA:
    ROUNDS = 8

    def __init__(self, passphrase: str, encrypt: bool):
        self.encrypt = encrypt
        self.sub_keys: list[int] = []
        # Generate subkeys from the passphrase(random generate on sender side, built up on receiver side)
        self.set_key(make_key(passphrase, 16))

    # generate subkeys and invert them to match invert rounds if decrypt mode
    def set_key(self, raw: bytes) -> None:
        temp = self._generate_subkeys(raw)
        self.sub_keys = temp if self.encrypt else self._invert_subkeys(temp)

    #
    @staticmethod
    def _generate_subkeys(u_key: bytes) -> list[int]:
        if len(u_key) != 16:
            raise ValueError("IDEA expects 128-bit key")

        # Rotate 128-bit key and extract 52 16-bit subkeys
        key128 = int.from_bytes(u_key, 'big')
        subkeys = []

        for i in range(IDEA.ROUNDS * 6 + 4):
            if i > 0 and i % 8 == 0:
                # 25-bit circular left shift of the 128-bit key
                key128 = ((key128 << 25) | (key128 >> 103)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            # Extract 16-bit subkeys from the rotated key
            subkey_position = i % 8
            bits_to_shift = 112 - (subkey_position * 16)
            subkey = (key128 >> bits_to_shift) & 0xFFFF
            subkeys.append(subkey)
        return subkeys

    # Modular addition mod 2^16
    @staticmethod
    def _add(x, y):
        return (x + y) & 0xFFFF

    # Additive inverse mod 2^16
    @staticmethod
    def _add_inv(x):
        return (-x) & 0xFFFF

    # IDEA uses multiplication mod 2^16 + 1
    @staticmethod
    def _mul(x, y):
        if x == 0: x = 0x10000
        if y == 0: y = 0x10000
        return (x * y % 0x10001) & 0xFFFF

    # Multiplicative inverse mod 2^16 + 1
    @classmethod
    def _mul_inv(cls, x):
        if x <= 1: return x
        inv = pow(x, -1, 0x10001)
        return inv & 0xFFFF

    # invert subkeys for decryption mode
    def _invert_subkeys(self, k: list[int]) -> list[int]:
        inv = [0] * 52
        p = 0
        # Output transformation last half round
        inv[48] = self._mul_inv(k[p])
        p += 1
        inv[49] = self._add_inv(k[p])
        p += 1
        inv[50] = self._add_inv(k[p])
        p += 1
        inv[51] = self._mul_inv(k[p])
        p += 1
        # Invert round subkeys (from round 8 down to 2)
        for r in range(7, 0, -1):
            i = r * 6
            inv[i + 4], inv[i + 5] = k[p], k[p + 1]
            p += 2
            inv[i] = self._mul_inv(k[p])
            p += 1
            inv[i + 2] = self._add_inv(k[p])
            p += 1
            inv[i + 1] = self._add_inv(k[p])
            p += 1
            inv[i + 3] = self._mul_inv(k[p])
            p += 1
        # Invert round 1 subkey's
        inv[4], inv[5] = k[p], k[p + 1]
        p += 2
        inv[0] = self._mul_inv(k[p])
        p += 1
        inv[1] = self._add_inv(k[p])
        p += 1
        inv[2] = self._add_inv(k[p])
        p += 1
        inv[3] = self._mul_inv(k[p])
        return inv

    # crypt\decrypt block - same action for both mode, differ in keys
    def crypt_block(self, data: bytearray, offset: int = 0) -> None:
        # Load 64-bit block into four 16-bit values
        x1 = concat16(data[offset], data[offset + 1])
        x2 = concat16(data[offset + 2], data[offset + 3])
        x3 = concat16(data[offset + 4], data[offset + 5])
        x4 = concat16(data[offset + 6], data[offset + 7])
        k = self.sub_keys
        p = 0
        # Perform 8 full IDEA rounds
        for _ in range(self.ROUNDS):
            y1 = self._mul(x1, k[p])
            y2 = self._add(x2, k[p + 1])
            y3 = self._add(x3, k[p + 2])
            y4 = self._mul(x4, k[p + 3])
            p += 4
            y5 = y1 ^ y3
            y6 = y2 ^ y4
            y7 = self._mul(y5, k[p])
            y8 = self._add(y6, y7)
            y9 = self._mul(y8, k[p + 1])
            y10 = self._add(y7, y9)
            p += 2
            # Prepare values for the next round
            x1, x2 = y1 ^ y9, y3 ^ y9
            x3, x4 = y2 ^ y10, y4 ^ y10
        # Output transformation half round after 8 rounds
        r0 = self._mul(x1, k[p])
        r1 = self._add(x3, k[p + 1])
        r2 = self._add(x2, k[p + 2])
        r3 = self._mul(x4, k[p + 3])
        # Write the result back into the byte array
        for i, r in enumerate((r0, r1, r2, r3)):
            data[offset + 2 * i] = (r >> 8) & 0xFF
            data[offset + 2 * i + 1] = r & 0xFF
