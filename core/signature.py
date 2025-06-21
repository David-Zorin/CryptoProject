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

# Compute modular inverse of k in the field mod p (needed to divide in finite-field arithmetic)
_modular_inverse = lambda k, m=p: pow(k % m, m - 2, m)
# Reduce x modulo p (keeps intermediate values inside the prime field)
_reduce_mod_p = lambda x: x % p


# ——— group operations ———
# Add two elliptic-curve points P and Q (core operation for building scalar multiples)
def _elliptic_curve_add(P, Q):
    # handle identity
    if P is None:
        return Q
    if Q is None:
        return P
    # P + (-P)  =  ∞
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    # doubling
    if P == Q:
        if P[1] == 0:  # tangent is vertical
            return None
        l = (3 * P[0] * P[0] + a) * _modular_inverse(2 * P[1]) % p
    # general addition
    else:
        l = (Q[1] - P[1]) * _modular_inverse(Q[0] - P[0]) % p
    x = _reduce_mod_p(l * l - P[0] - Q[0])
    y = _reduce_mod_p(l * (P[0] - x) - P[1])
    return (x, y)


# Multiply EC point P by scalar k via double-and-add (used to compute k·G or d·G)
def _elliptic_curve_mul(P, k):
    R = None
    addend = P
    while k:
        if k & 1:
            R = _elliptic_curve_add(R, addend)
        addend = _elliptic_curve_add(addend, addend)
        k >>= 1
    return R


# ——— RFC-6979 deterministic k ———
# Multiply EC point P by scalar k via double-and-add (used to compute k·G or d·G)
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
    # Build ECDSA keys: derive private_key from passphrase and compute public_key = private_key·G
    def __init__(self, passphrase: str):
        self.private_key = int.from_bytes(sha256(passphrase.encode()).digest(), 'big') % n or 1
        self.public_key = _elliptic_curve_mul(G, self.private_key)

    # Hash arbitrary message bytes into an integer z = H(M) via SHA-256 (prepares for signature math)
    @staticmethod
    def _hash_message(data: bytes) -> int:
        # Digital signature presentation Slide 33: “H(M)” is SHA-256 of the message, as specified in the course DSA Signature Creation
        return int.from_bytes(sha256(data).digest(), 'big')

    # Create ECDSA signature (r, s) on data to guarantee authenticity and integrity
    def create_signature(self, data: bytes) -> tuple[int, int]:
        # Digital signature presentation Slide 33: compute r = (k·G).x mod n and s = k⁻¹·(H(M) + r·d) mod n to form the signature (r,s)
        z = self._hash_message(data)
        while True:
            k = _det_k(self.private_key, z)
            x1, _ = _elliptic_curve_mul(G, k)
            r = x1 % n
            if r == 0:
                continue
            s = (_modular_inverse(k, n) * (z + r * self.private_key)) % n
            if s != 0:
                return (r, s)

    # Verify (r, s) against data and public_key Q to detect any tampering or wrong key
    @staticmethod
    def verify_signature(data: bytes, sig: tuple[int, int], Q: tuple[int, int]) -> bool:
        # Read a bundle, verify its signature, unwrap the session key, and decrypt back to the original file
        r, s = sig
        if not (1 <= r < n and 1 <= s < n):
            return False
        z = ECDSA._hash_message(data)
        w = _modular_inverse(s, n)
        u1, u2 = (z * w) % n, (r * w) % n
        X = _elliptic_curve_add(_elliptic_curve_mul(G, u1), _elliptic_curve_mul(Q, u2))
        return X is not None and (X[0] % n) == r
