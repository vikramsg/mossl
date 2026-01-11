"""Pure Mojo HMAC-SHA256 implementation.
Refactored to return the tag instead of using mut.
"""
from collections import List, InlineArray

from memory import Span

from crypto.sha256 import sha256


fn hmac_sha256(
    key: Span[UInt8], data: Span[UInt8]
) raises -> InlineArray[UInt8, 32]:
    """Computes the HMAC-SHA256 of the input data using the provided key.

    Args:
        key: The authentication key.
        data: The data to authenticate.

    Returns:
        The 32-byte authentication tag.
    """
    var k = InlineArray[UInt8, 64](0)
    if len(key) > 64:
        var k_tmp = sha256(key)
        for i in range(32):
            k[i] = k_tmp[i]
    else:
        for i in range(len(key)):
            k[i] = key[i]

    var i_key = InlineArray[UInt8, 64](0)
    var o_key = InlineArray[UInt8, 64](0)
    for i in range(64):
        i_key[i] = k[i] ^ 0x36
        o_key[i] = k[i] ^ 0x5C

    # Inner hash: sha256(i_key || data)
    var inner_data = List[UInt8](capacity=64 + len(data))
    for i in range(64):
        inner_data.append(i_key[i])
    inner_data.extend(data)

    var inner_hash = sha256(inner_data)

    # Outer hash: sha256(o_key || inner_hash)
    var outer_data = List[UInt8](capacity=64 + 32)
    for i in range(64):
        outer_data.append(o_key[i])
    for i in range(32):
        outer_data.append(inner_hash[i])

    return sha256(outer_data)


# Compatibility shim (deprecated)


fn hmac_sha256(key: List[UInt8], data: List[UInt8]) raises -> List[UInt8]:
    """Compatibility shim returning List[UInt8].





    Args:


        key: The authentication key.


        data: The data to authenticate.





    Returns:


        The computed 32-byte tag as a List[UInt8].


    """

    var t = hmac_sha256(Span(key), Span(data))

    var out = List[UInt8](capacity=32)

    for i in range(32):
        out.append(t[i])

    return out^
