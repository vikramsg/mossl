"""Pure Mojo HKDF implementation (RFC 5869).
Refactored to use Span for inputs and return values for outputs.
"""
from collections import List, InlineArray

from memory import Span

from crypto.hmac import hmac_sha256


fn hkdf_extract(
    salt: Span[UInt8], ikm: Span[UInt8]
) raises -> InlineArray[UInt8, 32]:
    """Performs HKDF extraction (RFC 5869).

    Args:
        salt: Optional salt value (a non-secret random value).
        ikm: Input keying material.

    Returns:
        The pseudorandom key (PRK).
    """
    if len(salt) == 0:
        var zeros = InlineArray[UInt8, 32](0)
        return hmac_sha256(zeros, ikm)
    return hmac_sha256(salt, ikm)


fn hkdf_expand(
    prk: Span[UInt8], info: Span[UInt8], length: Int
) raises -> List[UInt8]:
    """Performs HKDF expansion (RFC 5869).

    Args:
        prk: Pseudorandom key of at least HashLen octets.
        info: Optional context and application specific information.
        length: Length of output keying material in octets.

    Returns:
        The output keying material (OKM).
    """
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


fn hkdf_extract_sha384(
    salt: Span[UInt8], ikm: Span[UInt8]
) raises -> InlineArray[UInt8, 48]:
    """Performs HKDF extraction using SHA-384."""
    from crypto.hmac import hmac_sha384
    if len(salt) == 0:
        var zeros = InlineArray[UInt8, 48](0)
        return hmac_sha384(Span(zeros), ikm)
    return hmac_sha384(salt, ikm)


fn hkdf_expand_sha384(
    prk: Span[UInt8], info: Span[UInt8], length: Int
) raises -> List[UInt8]:
    """Performs HKDF expansion using SHA-384."""
    var hash_len = 48
    var n = (length + hash_len - 1) // hash_len
    var t_prev = List[UInt8]()
    var okm = List[UInt8](capacity=length)
    for _ in range(length):
        okm.append(0)
    var wrote = 0
    from crypto.hmac import hmac_sha384

    for i in range(1, n + 1):
        var input = List[UInt8](capacity=len(t_prev) + len(info) + 1)
        input.extend(t_prev)
        input.extend(info)
        input.append(UInt8(i))

        var t = hmac_sha384(prk, Span(input))

        var to_copy = min(hash_len, length - wrote)
        for j in range(to_copy):
            okm[wrote + j] = t[j]

        t_prev = List[UInt8](capacity=48)
        for j in range(48):
            t_prev.append(t[j])
        wrote += to_copy
    return okm^


# Compatibility shims (deprecated)
fn hkdf_extract(salt: List[UInt8], ikm: List[UInt8]) raises -> List[UInt8]:
    """Compatibility shim returning List[UInt8]."""
    var prk = hkdf_extract(Span(salt), Span(ikm))
    var out = List[UInt8](capacity=32)
    for i in range(32):
        out.append(prk[i])
    return out^


fn hkdf_expand(
    prk: List[UInt8], info: List[UInt8], length: Int
) raises -> List[UInt8]:
    """Compatibility shim for hkdf_expand."""
    return hkdf_expand(Span(prk), Span(info), length)
