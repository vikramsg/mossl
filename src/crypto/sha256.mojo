"""Optimized Mojo SHA-256 implementation.
Uses UInt32 and rotate_bits_right for performance.
Refactored to return the digest instead of using mut.
"""

from collections import List, InlineArray

from memory import Span


@always_inline
fn rotr(x: UInt32, n: Int) -> UInt32:
    return (x >> n) | (x << (32 - n))


@always_inline
fn sha256(data: Span[UInt8]) raises -> InlineArray[UInt8, 32]:
    """Computes the SHA-256 hash of the input data.

    Args:
        data: The data to hash.

    Returns:
        The computed 32-byte SHA-256 message digest.
    """
    var h = InlineArray[UInt32, 8](
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    )

    # Padding
    var msg_len = len(data)
    var pad_len = 64 - ((msg_len + 9) % 64)
    if pad_len == 64:
        pad_len = 0

    var padded = List[UInt8](capacity=msg_len + 1 + pad_len + 8)
    padded.extend(data)
    padded.append(0x80)
    for _ in range(pad_len):
        padded.append(0x00)

    var bit_len = UInt64(msg_len) * 8
    for i in range(8):
        padded.append(UInt8((bit_len >> (56 - i * 8)) & 0xFF))

    # Process blocks
    alias k = InlineArray[UInt32, 64](
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
        0xD807AA98,
        0x12835B01,
        0x243185BE,
        0x550C7DC3,
        0x72BE5D74,
        0x80DEB1FE,
        0x9BDC06A7,
        0xC19BF174,
        0xE49B69C1,
        0xEFBE4786,
        0x0FC19DC6,
        0x240CA1CC,
        0x2DE92C6F,
        0x4A7484AA,
        0x5CB0A9DC,
        0x76F988DA,
        0x983E5152,
        0xA831C66D,
        0xB00327C8,
        0xBF597FC7,
        0xC6E00BF3,
        0xD5A79147,
        0x06CA6351,
        0x14292967,
        0x27B70A85,
        0x2E1B2138,
        0x4D2C6DFC,
        0x53380D13,
        0x650A7354,
        0x766A0ABB,
        0x81C2C92E,
        0x92722C85,
        0xA2BFE8A1,
        0xA81A664B,
        0xC24B8B70,
        0xC76C51A3,
        0xD192E819,
        0xD6990624,
        0xF40E3585,
        0x106AA070,
        0x19A4C116,
        0x1E376C08,
        0x2748774C,
        0x34B0BCB5,
        0x391C0CB3,
        0x4ED8AA4A,
        0x5B9CCA4F,
        0x682E6FF3,
        0x748F82EE,
        0x78A5636F,
        0x84C87814,
        0x8CC70208,
        0x90BEFFFA,
        0xA4506CEB,
        0xBEF9A3F7,
        0xC67178F2,
    )

    for b in range(0, len(padded), 64):
        var w = InlineArray[UInt32, 64](0)
        for i in range(16):
            w[i] = (
                (UInt32(padded[b + i * 4]) << 24)
                | (UInt32(padded[b + i * 4 + 1]) << 16)
                | (UInt32(padded[b + i * 4 + 2]) << 8)
                | UInt32(padded[b + i * 4 + 3])
            )
        for i in range(16, 64):
            var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1

        var a = h[0]
        var b_v = h[1]
        var c = h[2]
        var d = h[3]
        var e = h[4]
        var f = h[5]
        var g = h[6]
        var h_v = h[7]

        for i in range(64):
            var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            var ch = (e & f) ^ ((~e) & g)
            var temp1 = h_v + S1 + ch + k[i] + w[i]
            var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            var maj = (a & b_v) ^ (a & c) ^ (b_v & c)
            var temp2 = S0 + maj

            h_v = g
            g = f
            f = e
            e = d + temp1
            d = c
            c = b_v
            b_v = a
            a = temp1 + temp2

        h[0] += a
        h[1] += b_v
        h[2] += c
        h[3] += d
        h[4] += e
        h[5] += f
        h[6] += g
        h[7] += h_v

    var digest = InlineArray[UInt8, 32](0)
    for i in range(8):
        digest[i * 4] = UInt8((h[i] >> 24) & 0xFF)
        digest[i * 4 + 1] = UInt8((h[i] >> 16) & 0xFF)
        digest[i * 4 + 2] = UInt8((h[i] >> 8) & 0xFF)
        digest[i * 4 + 3] = UInt8(h[i] & 0xFF)
    return digest


# Compatibility shim


fn sha256_bytes(data: List[UInt8]) raises -> List[UInt8]:
    """Compatibility shim returning List[UInt8].





    Args:


        data: The data to hash.





    Returns:


        The computed 32-byte digest as a List[UInt8].


    """

    var d = sha256(Span(data))

    var out = List[UInt8](capacity=32)

    for i in range(32):
        out.append(d[i])

    return out^
