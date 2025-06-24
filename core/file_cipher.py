from pathlib import Path
from typing import Callable, Optional
from crypto.cbc import CBC
CHUNK = 2 << 20 # 2^20 ~ 2MB

# FileCipher: process our file using IDEA-CBC encrypt / decrypt 1 chunk at a time
class FileCipher:
    # initialize to encrypt mode
    def __init__(self, src: str, dst: str, passphrase: str,
                 encrypt: bool = True,
                 progress: Optional[Callable[[float], None]] = None):
        self.src, self.dst = Path(src), Path(dst)
        self.passphrase, self.encrypt = passphrase, encrypt
        self.progress = progress or (lambda *_: None)
        self.cbc = CBC(passphrase, encrypt)

    # read, pad with \0, encrypt\decrypt using IDEA-CBC, write loop over the file in chunks
    def run(self) -> None:
        in_len = self.src.stat().st_size
        processed = 0
        with self.src.open('rb') as fin, self.dst.open('wb') as fout:
            while chunk := fin.read(CHUNK):
                processed += len(chunk)
                # transform every chunk first
                out_chunk = self._transform(chunk)
                # if decrypting the last chunk, strip the \0 padding
                if (not self.encrypt) and processed == in_len:
                    out_chunk = out_chunk.rstrip(b'\0')
                fout.write(out_chunk)
                self.progress(processed / in_len)

    # _transform: pad chunk to 8 byte multiplier, call cbc.process on 8 byte each time
    def _transform(self, chunk: bytes) -> bytes:
        # pad so length % 8 == 0
        pad_len = (-len(chunk)) % 8
        chunk += b'\0'*pad_len
        out = bytearray()
        for i in range(0, len(chunk), 8):
            out += self.cbc.process(chunk[i:i+8])
        return bytes(out)
