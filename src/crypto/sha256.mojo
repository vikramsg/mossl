"""Optimized Mojo SHA-256 implementation."""
from builtin.dtype import DType
from collections import List, InlineArray

from bit import rotate_bits_right

from crypto.bytes import zeroize


fn k_constants() -> InlineArray[UInt32, 64]:
    return InlineArray[UInt32, 64](
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


@always_inline
fn ch(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return (x & y) ^ (~x & z)


@always_inline
fn maj(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return (x & y) ^ (x & z) ^ (y & z)


@always_inline
fn big_sigma0(x: UInt32) -> UInt32:
    return (
        rotate_bits_right[2](x)
        ^ rotate_bits_right[13](x)
        ^ rotate_bits_right[22](x)
    )


@always_inline
fn big_sigma1(x: UInt32) -> UInt32:
    return (
        rotate_bits_right[6](x)
        ^ rotate_bits_right[11](x)
        ^ rotate_bits_right[25](x)
    )


@always_inline
fn small_sigma0(x: UInt32) -> UInt32:
    return rotate_bits_right[7](x) ^ rotate_bits_right[18](x) ^ (x >> 3)


@always_inline
fn small_sigma1(x: UInt32) -> UInt32:
    return rotate_bits_right[17](x) ^ rotate_bits_right[19](x) ^ (x >> 10)


fn sha256_bytes(data_in: List[UInt8]) -> List[UInt8]:
    var data = data_in.copy()

    # Padding
    data.append(0x80)
    while (len(data) % 64) != 56:
        data.append(0)

    var bit_len = UInt64(len(data_in)) * 8
    for i in range(8):
        var shift = (7 - i) * 8
        data.append(UInt8((bit_len >> shift) & 0xFF))

    var h0: UInt32 = 0x6A09E667
    var h1: UInt32 = 0xBB67AE85
    var h2: UInt32 = 0x3C6EF372
    var h3: UInt32 = 0xA54FF53A
    var h4: UInt32 = 0x510E527F
    var h5: UInt32 = 0x9B05688C
    var h6: UInt32 = 0x1F83D9AB
    var h7: UInt32 = 0x5BE0CD19

    alias k = k_constants()
    var w = InlineArray[UInt32, 64](0)

    var chunk = 0
    while chunk < len(data):
        # Message schedule
        for t in range(16):
            var base = chunk + t * 4
            var word = (
                (UInt32(data[base]) << 24)
                | (UInt32(data[base + 1]) << 16)
                | (UInt32(data[base + 2]) << 8)
                | UInt32(data[base + 3])
            )
            w[t] = word

        for t in range(16, 64):
            w[t] = (
                small_sigma1(w[t - 2])
                + w[t - 7]
                + small_sigma0(w[t - 15])
                + w[t - 16]
            )

        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4
        var f = h5
        var g = h6
        var h = h7

        for t in range(64):
            var temp1 = h + big_sigma1(e) + ch(e, f, g) + k[t] + w[t]
            var temp2 = big_sigma0(a) + maj(a, b, c)
            h = g
            g = f
            f = e
            e = d + temp1
            d = c
            c = b
            b = a
            a = temp1 + temp2

        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e
        h5 += f
        h6 += g
        h7 += h

        chunk += 64

    # Final hash
    var out = List[UInt8](capacity=32)
    var states = InlineArray[UInt32, 8](h0, h1, h2, h3, h4, h5, h6, h7)
    for i in range(8):
        var word = states[i]
        out.append(UInt8((word >> 24) & 0xFF))
        out.append(UInt8((word >> 16) & 0xFF))
        out.append(UInt8((word >> 8) & 0xFF))
        out.append(UInt8(word & 0xFF))

    # Security: clear message schedule and intermediate data
    for i in range(64):
        w[i] = 0
    zeroize(data)
    return out^
