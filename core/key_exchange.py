"""
Simple Merkle–Hellman super‑increasing knapsack to wrap the 128‑bit IDEA key.
Not cryptographically strong for real use – fits the course requirement.
"""
import random
from math import gcd
from typing import List, Tuple


def _inv_mod(a, m): return pow(a, -1, m)


class MHK:
    def __init__(self, n: int = 128):
        # Generate a proper super-increasing sequence
        self._w = []
        current_sum = 0
        for i in range(n):
            # Each element must be greater than the sum of all previous elements
            min_val = current_sum + 1
            next_val = random.randint(min_val, min_val + random.randint(1, 10))
            self._w.append(next_val)
            current_sum += next_val
        
        self._q = random.randint(sum(self._w) + 1, 2 * sum(self._w))
        self._r = random.randrange(2, self._q)
        while gcd(self._r, self._q) != 1:
            self._r = random.randrange(2, self._q)
        self.public = [(self._r * w) % self._q for w in self._w]

    # ---------------- encryption / decryption ----------------
    def encrypt(self, key: bytes) -> int:
        bits = ''.join(f'{b:08b}' for b in key)
        s = sum(int(b) * pk for b, pk in zip(bits, self.public))
        return s

    def decrypt(self, s: int) -> bytes:
        total = (s * _inv_mod(self._r, self._q)) % self._q
        bits: List[int] = [0] * len(self._w)
        for i in reversed(range(len(self._w))):
            if total >= self._w[i]:
                bits[i] = 1
                total -= self._w[i]
        bitstr = ''.join(map(str, bits))
        byts = [int(bitstr[i:i + 8], 2) for i in range(0, len(bitstr), 8)]
        return bytes(byts)
