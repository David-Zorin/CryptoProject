from pathlib import Path
import json, struct, os, random
from hashlib import sha256
from core.key_exchange import MHK
from core.file_cipher import FileCipher
from core.signature import ECDSA


# Build Merkle–Hellman knapsack from passphrase so we can wrap / unwrap the session key
def _build_mh_key(pw):
    seed = int.from_bytes(sha256(pw.encode()).digest(), 'big') & 0xffffffff # random seed by the passphrase insert by user
    st = random.getstate()
    random.seed(seed)
    obj = MHK()
    random.setstate(st)
    return obj


# ——— sender ———
# Encrypt a file with a random private session key, wrap that key(MHK), sign ciphertext, and bundle all parts
def send(src, dst, pw, prog=lambda *_: None):
    session_key = os.urandom(16)
    tmp = Path(f"{dst}.enc")
    FileCipher(src, str(tmp), session_key.hex(), True, prog).run() # encrypt the file and write it to tmp path
    ciphertext = tmp.read_bytes() # load locally the encrypted file
    tmp.unlink() # delete the file at tmp path

    mh = _build_mh_key(pw)
    ecd = ECDSA(pw)
    hdr = json.dumps(
        {
            "ck": mh.encrypt(session_key), # knapsack sum
            "sig": ecd.create_signature(ciphertext), # ECDSA signature over our ciphertext
            "public_key": ecd.public_key # ECDSA public key
        }
    ).encode()
    # write a bundle of header hdr and the ciphertext for the receiver
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
    # recreate the sender private key used for encryption
    session_key = _build_mh_key(pw).decrypt(header["ck"])[-16:]
    tmp = Path(f"{dst}.dec")
    tmp.write_bytes(ciphertext)
    FileCipher(str(tmp), dst, session_key.hex(), False, prog).run()
    tmp.unlink()
    return header
