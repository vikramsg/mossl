"""TLS 1.3 record-layer nonce and sequence handling."""
from collections import List

from crypto.aes_gcm import aes_gcm_seal


fn build_nonce(iv: List[UInt8], seq: UInt64) -> List[UInt8]:
    # Nonce = iv XOR (0^32 || seq^64) per TLS 1.3.
    var out = List[UInt8]()
    var i = 0
    while i < len(iv):
        out.append(iv[i])
        i += 1
    var seq_bytes = List[UInt8]()
    i = 0
    while i < 8:
        var shift = (7 - i) * 8
        seq_bytes.append(UInt8((seq >> shift) & UInt64(0xFF)))
        i += 1
    i = 0
    while i < 8:
        var idx = 4 + i
        out[idx] = UInt8(out[idx] ^ seq_bytes[i])
        i += 1
    return out^


struct RecordSealer:
    var key: List[UInt8]
    var iv: List[UInt8]
    var seq: UInt64

    fn __init__(out self, in_key: List[UInt8], in_iv: List[UInt8]):
        self.key = in_key.copy()
        self.iv = in_iv.copy()
        self.seq = UInt64(0)

    fn seal(
        mut self, aad: List[UInt8], plaintext: List[UInt8]
    ) -> (List[UInt8], List[UInt8], List[UInt8]):
        var nonce = build_nonce(self.iv, self.seq)
        var sealed = aes_gcm_seal(self.key, nonce, aad, plaintext)
        self.seq += UInt64(1)
        return (sealed[0].copy(), sealed[1].copy(), nonce^)
