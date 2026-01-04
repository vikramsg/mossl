"""Pure Mojo HMAC-SHA256 implementation."""
from collections import List
from crypto.sha256 import sha256_bytes
from crypto.bytes import concat_bytes, zeros

fn pad_key(key: List[UInt8], block_size: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for b in key:
        out.append(b)
    while len(out) < block_size:
        out.append(UInt8(0))
    return out^

fn hmac_sha256(key: List[UInt8], data: List[UInt8]) -> List[UInt8]:
    var k = key.copy()
    if len(k) > 64:
        k = sha256_bytes(k)
    k = pad_key(k, 64)

    var o_key = List[UInt8]()
    var i_key = List[UInt8]()
    var i = 0
    while i < 64:
        o_key.append(UInt8(k[i] ^ UInt8(0x5c)))
        i_key.append(UInt8(k[i] ^ UInt8(0x36)))
        i += 1

    var inner = sha256_bytes(concat_bytes(i_key, data))
    return sha256_bytes(concat_bytes(o_key, inner))
