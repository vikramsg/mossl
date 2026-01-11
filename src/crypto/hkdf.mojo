"""Pure Mojo HKDF implementation (RFC 5869).
Refactored to use Span for inputs and return values for outputs.
"""
from collections import List, InlineArray

from memory import Span

from crypto.hmac import hmac_sha256


fn hkdf_extract(
    salt: Span[UInt8], ikm: Span[UInt8]
) raises -> InlineArray[UInt8, 32]:
    if len(salt) == 0:
        var zeros = InlineArray[UInt8, 32](0)
        return hmac_sha256(zeros, ikm)
    return hmac_sha256(salt, ikm)


fn hkdf_expand(
    prk: Span[UInt8], info: Span[UInt8], length: Int
) raises -> List[UInt8]:
    var hash_len = 32
    var n = (length + hash_len - 1) // hash_len
    var t_prev = List[UInt8]()
    var okm = List[UInt8](capacity=length)
    for _ in range(length):
        okm.append(0)
    var wrote = 0

    for i in range(1, n + 1):
        var input = List[UInt8](capacity=len(t_prev) + len(info) + 1)
        for j in range(len(t_prev)):
            input.append(t_prev[j])
        for j in range(len(info)):
            input.append(info[j])
        input.append(UInt8(i))

        var t = hmac_sha256(prk, input)

        var to_copy = min(hash_len, length - wrote)
        for j in range(to_copy):
            okm[wrote + j] = t[j]

        t_prev = List[UInt8](capacity=32)
        for j in range(32):
            t_prev.append(t[j])
        wrote += to_copy
    return okm^


# Compatibility shims (deprecated)
fn hkdf_extract(salt: List[UInt8], ikm: List[UInt8]) -> List[UInt8]:
    try:
        var prk = hkdf_extract(Span(salt), Span(ikm))
        var out = List[UInt8](capacity=32)
        for i in range(32):
            out.append(prk[i])
        return out^
    except:
        return List[UInt8]()


fn hkdf_expand(prk: List[UInt8], info: List[UInt8], length: Int) -> List[UInt8]:
    try:
        return hkdf_expand(Span(prk), Span(info), length)
    except:
        return List[UInt8]()
