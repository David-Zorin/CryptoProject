from pathlib import Path
from typing import Callable, Optional
from crypto.cbc import CBC
from crypto.utils import xor
CHUNK = 2 << 20     # 2 MB

class FileCipher:
    """Encrypt / Decrypt files with IDEA‑CBC + optional sign / verify."""

    def __init__(self, src: str, dst: str, passphrase: str,
                 encrypt: bool = True,
                 progress: Optional[Callable[[float], None]] = None):
        self.src, self.dst = Path(src), Path(dst)
        self.passphrase, self.encrypt = passphrase, encrypt
        self.progress = progress or (lambda *_: None)
        self.cbc = CBC(passphrase, encrypt)

    # ---- public -------------------------------------------------------------
    def run(self) -> None:
        in_len = self.src.stat().st_size
        processed = 0
        with self.src.open('rb') as fin, self.dst.open('wb') as fout:
            while chunk := fin.read(CHUNK):
                processed += len(chunk)
                # transform every chunk first
                out_chunk = self._transform(chunk)
                # if decrypting the *last* chunk, strip the zero-padding
                if (not self.encrypt) and processed == in_len:
                    out_chunk = out_chunk.rstrip(b'\0')
                fout.write(out_chunk)
                self.progress(processed / in_len)

    # ---- helpers ------------------------------------------------------------
    def _transform(self, chunk: bytes) -> bytes:
        # pad so length % 8 == 0
        pad_len = (-len(chunk)) % 8
        chunk += b'\0'*pad_len
        out = bytearray()
        for i in range(0, len(chunk), 8):
            out += self.cbc.process(chunk[i:i+8])
        return bytes(out)
