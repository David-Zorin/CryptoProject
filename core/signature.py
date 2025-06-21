"""
Hardened ECDSA (secp192r1) – pure-Python, RFC-6979-deterministic, no deps.
"""
from hashlib import sha256
from random import SystemRandom

# ——— curve params (SECP192R1 = NIST P-192) ———
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
n = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
G = (Gx, Gy)

# ——— finite-field helpers ———
_inv = lambda k, m=p: pow(k % m, m - 2, m)  # Fermat inverse mod m
_mod = lambda x: x % p


# ——— group operations ———
def _ec_add(P, Q):
    # handle identity
    if P is None:  return Q
    if Q is None:  return P
    # P + (-P)  =  ∞
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    # doubling
    if P == Q:
        if P[1] == 0:  # tangent is vertical
            return None
        l = (3 * P[0] * P[0] + a) * _inv(2 * P[1]) % p
    # general addition
    else:
        l = (Q[1] - P[1]) * _inv(Q[0] - P[0]) % p
    x = _mod(l * l - P[0] - Q[0])
    y = _mod(l * (P[0] - x) - P[1])
    return (x, y)


def _ec_mul(P, k):
    R = None
    addend = P
    while k:
        if k & 1:
            R = _ec_add(R, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return R


# ——— RFC-6979 deterministic k ———
def _det_k(d, h):
    v = b'\x01' * 32
    k = b'\x00' * 32
    priv = d.to_bytes(24, 'big')
    hsh = h.to_bytes(32, 'big')
    import hmac
    k = hmac.new(k, v + b'\x00' + priv + hsh, sha256).digest()
    v = hmac.new(k, v, sha256).digest()
    k = hmac.new(k, v + b'\x01' + priv + hsh, sha256).digest()
    v = hmac.new(k, v, sha256).digest()
    while True:
        v = hmac.new(k, v, sha256).digest()
        cand = int.from_bytes(v, 'big') % n
        if 1 <= cand < n:
            return cand
        k = hmac.new(k, v + b'\x00', sha256).digest()
        v = hmac.new(k, v, sha256).digest()


# ——— main API ———
class ECDSA:
    def __init__(self, passphrase: str):
        self.d = int.from_bytes(sha256(passphrase.encode()).digest(), 'big') % n or 1
        self.Q = _ec_mul(G, self.d)

    @staticmethod
    def _h(data: bytes) -> int:
        return int.from_bytes(sha256(data).digest(), 'big')

    def sign(self, data: bytes) -> tuple[int, int]:
        z = self._h(data)
        while True:
            k = _det_k(self.d, z)
            x1, _ = _ec_mul(G, k)
            r = x1 % n
            if r == 0:
                continue
            s = (_inv(k, n) * (z + r * self.d)) % n
            if s != 0:
                return (r, s)

    @staticmethod
    def verify(data: bytes, sig: tuple[int, int], Q: tuple[int, int]) -> bool:
        r, s = sig
        if not (1 <= r < n and 1 <= s < n):
            return False
        z = ECDSA._h(data)
        w = _inv(s, n)
        u1, u2 = (z * w) % n, (r * w) % n
        X = _ec_add(_ec_mul(G, u1), _ec_mul(Q, u2))
        return X is not None and (X[0] % n) == r
