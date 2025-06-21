from pathlib import Path
import json, struct, os, random
from hashlib import sha256
from core.key_exchange import MHK
from core.file_cipher import FileCipher
from core.signature import ECDSA                     # ← import the new class

# ——— deterministic Merkle–Hellman (unchanged) ———
def _mhk(pw):
    seed = int.from_bytes(sha256(pw.encode()).digest(), 'big') & 0xffffffff
    st = random.getstate()
    random.seed(seed)
    obj = MHK()
    random.setstate(st)
    return obj

# ——— sender ———
def send(src, dst, pw, prog=lambda *_: None):
    key = os.urandom(16)
    tmp = Path(f"{dst}.enc")
    FileCipher(src, str(tmp), key.hex(), True, prog).run()
    ct  = tmp.read_bytes()
    tmp.unlink()

    mh   = _mhk(pw)
    ecd  = ECDSA(pw)
    hdr  = json.dumps(
        {"ck": mh.encrypt(key), "sig": ecd.sign(ct), "Q": ecd.Q}
    ).encode()

    with open(dst, "wb") as f:
        f.write(struct.pack(">I", len(hdr)))
        f.write(hdr)
        f.write(ct)
    return hdr

# ——— receiver ———
def receive(src, dst, pw, prog=lambda *_: None):
    with open(src, "rb") as f:
        hlen = struct.unpack(">I", f.read(4))[0]
        hdr  = json.loads(f.read(hlen))
        ct   = f.read()

    if not ECDSA.verify(ct, tuple(hdr["sig"]), tuple(hdr["Q"])):
        raise ValueError("Signature invalid – file corrupted or tampered")

    key = _mhk(pw).decrypt(hdr["ck"])[-16:]
    tmp = Path(f"{dst}.dec")
    tmp.write_bytes(ct)
    FileCipher(str(tmp), dst, key.hex(), False, prog).run()
    tmp.unlink()
    return hdr
