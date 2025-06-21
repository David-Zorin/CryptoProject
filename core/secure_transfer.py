from pathlib import Path
import json, struct, os, random
from hashlib import sha256
from core.key_exchange import MHK
from core.file_cipher import FileCipher
from core.signature import ECDSA  # ← import the new class


# ——— deterministic Merkle–Hellman (unchanged) ———
# Rebuild Merkle–Hellman knapsack from passphrase so we can wrap/unwrap the session key
def _build_mh_key(pw):
    seed = int.from_bytes(sha256(pw.encode()).digest(), 'big') & 0xffffffff
    st = random.getstate()
    random.seed(seed)
    obj = MHK()
    random.setstate(st)
    return obj


# ——— sender ———
# Encrypt a file with a fresh session key, wrap that key, sign ciphertext, and bundle all parts
def send(src, dst, pw, prog=lambda *_: None):
    session_key = os.urandom(16)
    tmp = Path(f"{dst}.enc")
    FileCipher(src, str(tmp), session_key.hex(), True, prog).run()
    ciphertext = tmp.read_bytes()
    tmp.unlink()

    mh = _build_mh_key(pw)
    ecd = ECDSA(pw)
    hdr = json.dumps(
        {"ck": mh.encrypt(session_key), "sig": ecd.create_signature(ciphertext), "public_key": ecd.public_key}
    ).encode()

    with open(dst, "wb") as f:
        f.write(struct.pack(">I", len(hdr)))
        f.write(hdr)
        f.write(ciphertext)
    return hdr


# ——— receiver ———
# Read a bundle, verify its signature, unwrap the session key, and decrypt back to the original file
def receive(src, dst, pw, prog=lambda *_: None):
    with open(src, "rb") as f:
        header_len = struct.unpack(">I", f.read(4))[0]
        header = json.loads(f.read(header_len))
        ciphertext = f.read()

    if not ECDSA.verify_signature(ciphertext, tuple(header["sig"]), tuple(header["public_key"])):
        raise ValueError("Signature invalid – file corrupted or tampered")

    session_key = _build_mh_key(pw).decrypt(header["ck"])[-16:]
    tmp = Path(f"{dst}.dec")
    tmp.write_bytes(ciphertext)
    FileCipher(str(tmp), dst, session_key.hex(), False, prog).run()
    tmp.unlink()
    return header
