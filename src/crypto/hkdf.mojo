"""Pure Mojo HKDF implementation (RFC 5869)."""
from collections import List

from crypto.bytes import concat_bytes, zeros
from crypto.hmac import hmac_sha256

fn hkdf_extract(salt: List[UInt8], ikm: List[UInt8]) -> List[UInt8]:
    var s = salt.copy()
    if len(s) == 0:
        s = zeros(32)
    return hmac_sha256(s, ikm)


fn hkdf_expand(prk: List[UInt8], info: List[UInt8], length: Int) -> List[UInt8]:
    var hash_len = 32
    if length <= 0:
        return List[UInt8]()
    var n = (length + hash_len - 1) // hash_len
    var t_prev = List[UInt8]()
    var okm = List[UInt8]()
    var i = 1
    while i <= n:
        var input = concat_bytes(t_prev, info)
        input.append(UInt8(i))
        var t = hmac_sha256(prk, input)
        for b in t:
            okm.append(b)
        t_prev = t.copy()
        i += 1

    while len(okm) > length:
        _ = okm.pop()
    return okm^
