from hashlib import sha256
from random import SystemRandom

# curve params from standard efficient cryptology group (SECG) with secg192r1 - 192 bits for prime number p
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
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: # case 2 of addition on E
        return None
    # doubling
    if P == Q:
        if P[1] == 0:  # denominator can't be a zero
            return None
        l = (3 * P[0] * P[0] + a) * _modular_inverse(2 * P[1]) % p # case 3 of addition on E
    # general addition
    else:
        l = (Q[1] - P[1]) * _modular_inverse(Q[0] - P[0]) % p # case 1 of addition on E
    x = _reduce_mod_p(l * l - P[0] - Q[0])
    y = _reduce_mod_p(l * (P[0] - x) - P[1])
    return (x, y)


# Multiply EC point P by scalar k via double-and-add (used to compute k·G or d·G)
def _elliptic_curve_mul(P, private_key):
    R = None
    start_point = P
    while private_key:
        if private_key & 1: # if LSB is 1(odd), at least 1 elliptic_curve_add need to be made
            R = _elliptic_curve_add(R, start_point)
        start_point = _elliptic_curve_add(start_point, start_point)
        private_key >>= 1 # 1 in-place bitwise right shift
    return R

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
        L_n = sha256(data).digest()  # 32 bytes = 256 bits
        e = int.from_bytes(L_n, 'big')
        z = e >> 64  # 256 − 192 = 64
        return z

    # Create ECDSA signature
    def create_signature(self, data: bytes) -> tuple[int, int]:
        # compute r = (k·G).x1 mod n and s = k⁻¹·(H(M) + r·d) mod n to form the signature (r,s)
        import hmac
        # Iterated hash function (RFC 6979) steps for making random_k a deterministic choice
        z = self._hash_message(data) # step 1
        v = b'\x01' * 32
        k = b'\x00' * 32
        private_key = self.private_key.to_bytes(24, 'big')
        hsh = z.to_bytes(32, 'big')
        k = hmac.new(k, v + b'\x00' + private_key + hsh, sha256).digest()
        v = hmac.new(k, v, sha256).digest()
        k = hmac.new(k, v + b'\x01' + private_key + hsh, sha256).digest()
        v = hmac.new(k, v, sha256).digest()
        while True:
            v = hmac.new(k, v, sha256).digest()
            random_k = int.from_bytes(v, 'big') % n
            if 1 <= random_k < n:
                x1, _ = _elliptic_curve_mul(G, random_k)
                r = x1 % n
                if r != 0:
                    s = (_modular_inverse(random_k, n) * (z + r * self.private_key)) % n
                    if s != 0:
                        return (r, s)
            k = hmac.new(k, v + b'\x00', sha256).digest()
            v = hmac.new(k, v, sha256).digest()

    # Verify (r, s) against data and public_key Q to detect any tampering or wrong key
    @staticmethod
    def verify_signature(data: bytes, sig: tuple[int, int], Q: tuple[int, int]) -> bool:
        # Read a bundle, verify its signature, unwrap the session key, and decrypt back to the original file
        r, s = sig
        if not (1 <= r < n and 1 <= s < n): # sanity check - implementation won't allow this to occur
            return False
        z = ECDSA._hash_message(data) # step 1
        w = _modular_inverse(s, n) # step 3
        u1, u2 = (z * w) % n, (r * w) % n # step 4
        X = _elliptic_curve_add(_elliptic_curve_mul(G, u1), _elliptic_curve_mul(Q, u2)) # step 5
        return X is not None and (X[0] % n) == r
        # if X is None:
        #     return False
        # else:
        #     x1, _ = X
        #     return x1 % n == 0

