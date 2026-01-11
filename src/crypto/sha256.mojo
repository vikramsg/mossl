"""Pure Mojo SHA-256 implementation."""
from collections import List

fn mask32(x: Int) -> Int:
    return x & 0xFFFFFFFF


fn rotr(x: Int, n: Int) -> Int:
    return mask32((x >> n) | (x << (32 - n)))


fn ch(x: Int, y: Int, z: Int) -> Int:
    return mask32((x & y) ^ ((~x) & z))


fn maj(x: Int, y: Int, z: Int) -> Int:
    return mask32((x & y) ^ (x & z) ^ (y & z))


fn big_sigma0(x: Int) -> Int:
    return mask32(rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))


fn big_sigma1(x: Int) -> Int:
    return mask32(rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))


fn small_sigma0(x: Int) -> Int:
    return mask32(rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3))


fn small_sigma1(x: Int) -> Int:
    return mask32(rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10))


fn k_constants() -> List[Int]:
    var k = List[Int]()
    k.append(0x428A2F98)
    k.append(0x71374491)
    k.append(0xB5C0FBCF)
    k.append(0xE9B5DBA5)
    k.append(0x3956C25B)
    k.append(0x59F111F1)
    k.append(0x923F82A4)
    k.append(0xAB1C5ED5)
    k.append(0xD807AA98)
    k.append(0x12835B01)
    k.append(0x243185BE)
    k.append(0x550C7DC3)
    k.append(0x72BE5D74)
    k.append(0x80DEB1FE)
    k.append(0x9BDC06A7)
    k.append(0xC19BF174)
    k.append(0xE49B69C1)
    k.append(0xEFBE4786)
    k.append(0x0FC19DC6)
    k.append(0x240CA1CC)
    k.append(0x2DE92C6F)
    k.append(0x4A7484AA)
    k.append(0x5CB0A9DC)
    k.append(0x76F988DA)
    k.append(0x983E5152)
    k.append(0xA831C66D)
    k.append(0xB00327C8)
    k.append(0xBF597FC7)
    k.append(0xC6E00BF3)
    k.append(0xD5A79147)
    k.append(0x06CA6351)
    k.append(0x14292967)
    k.append(0x27B70A85)
    k.append(0x2E1B2138)
    k.append(0x4D2C6DFC)
    k.append(0x53380D13)
    k.append(0x650A7354)
    k.append(0x766A0ABB)
    k.append(0x81C2C92E)
    k.append(0x92722C85)
    k.append(0xA2BFE8A1)
    k.append(0xA81A664B)
    k.append(0xC24B8B70)
    k.append(0xC76C51A3)
    k.append(0xD192E819)
    k.append(0xD6990624)
    k.append(0xF40E3585)
    k.append(0x106AA070)
    k.append(0x19A4C116)
    k.append(0x1E376C08)
    k.append(0x2748774C)
    k.append(0x34B0BCB5)
    k.append(0x391C0CB3)
    k.append(0x4ED8AA4A)
    k.append(0x5B9CCA4F)
    k.append(0x682E6FF3)
    k.append(0x748F82EE)
    k.append(0x78A5636F)
    k.append(0x84C87814)
    k.append(0x8CC70208)
    k.append(0x90BEFFFA)
    k.append(0xA4506CEB)
    k.append(0xBEF9A3F7)
    k.append(0xC67178F2)
    return k^


fn sha256_bytes(data_in: List[UInt8]) -> List[UInt8]:
    var data = List[UInt8]()
    for b in data_in:
        data.append(b)

    data.append(UInt8(0x80))
    while (len(data) % 64) != 56:
        data.append(UInt8(0))

    var bit_len = UInt64(len(data_in)) * UInt64(8)
    var i = 0
    while i < 8:
        var shift = (7 - i) * 8
        data.append(UInt8((bit_len >> shift) & UInt64(0xFF)))
        i += 1

    var h0 = 0x6A09E667
    var h1 = 0xBB67AE85
    var h2 = 0x3C6EF372
    var h3 = 0xA54FF53A
    var h4 = 0x510E527F
    var h5 = 0x9B05688C
    var h6 = 0x1F83D9AB
    var h7 = 0x5BE0CD19

    var k = k_constants()

    var chunk = 0
    while chunk < len(data):
        var w = List[Int]()
        var t = 0
        while t < 16:
            var base = chunk + t * 4
            var b0 = Int(data[base])
            var b1 = Int(data[base + 1])
            var b2 = Int(data[base + 2])
            var b3 = Int(data[base + 3])
            w.append(mask32((b0 << 24) | (b1 << 16) | (b2 << 8) | b3))
            t += 1

        while t < 64:
            var s0 = small_sigma0(w[t - 15])
            var s1 = small_sigma1(w[t - 2])
            w.append(mask32(w[t - 16] + s0 + w[t - 7] + s1))
            t += 1

        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4
        var f = h5
        var g = h6
        var h = h7

        t = 0
        while t < 64:
            var temp1 = mask32(h + big_sigma1(e) + ch(e, f, g) + k[t] + w[t])
            var temp2 = mask32(big_sigma0(a) + maj(a, b, c))
            h = g
            g = f
            f = e
            e = mask32(d + temp1)
            d = c
            c = b
            b = a
            a = mask32(temp1 + temp2)
            t += 1

        h0 = mask32(h0 + a)
        h1 = mask32(h1 + b)
        h2 = mask32(h2 + c)
        h3 = mask32(h3 + d)
        h4 = mask32(h4 + e)
        h5 = mask32(h5 + f)
        h6 = mask32(h6 + g)
        h7 = mask32(h7 + h)

        chunk += 64

    var out = List[UInt8]()
    var word = h0
    out.append(UInt8((word >> 24) & 0xFF))
    out.append(UInt8((word >> 16) & 0xFF))
    out.append(UInt8((word >> 8) & 0xFF))
    out.append(UInt8(word & 0xFF))
    word = h1
    out.append(UInt8((word >> 24) & 0xFF))
    out.append(UInt8((word >> 16) & 0xFF))
    out.append(UInt8((word >> 8) & 0xFF))
    out.append(UInt8(word & 0xFF))
    word = h2
    out.append(UInt8((word >> 24) & 0xFF))
    out.append(UInt8((word >> 16) & 0xFF))
    out.append(UInt8((word >> 8) & 0xFF))
    out.append(UInt8(word & 0xFF))
    word = h3
    out.append(UInt8((word >> 24) & 0xFF))
    out.append(UInt8((word >> 16) & 0xFF))
    out.append(UInt8((word >> 8) & 0xFF))
    out.append(UInt8(word & 0xFF))
    word = h4
    out.append(UInt8((word >> 24) & 0xFF))
    out.append(UInt8((word >> 16) & 0xFF))
    out.append(UInt8((word >> 8) & 0xFF))
    out.append(UInt8(word & 0xFF))
    word = h5
    out.append(UInt8((word >> 24) & 0xFF))
    out.append(UInt8((word >> 16) & 0xFF))
    out.append(UInt8((word >> 8) & 0xFF))
    out.append(UInt8(word & 0xFF))
    word = h6
    out.append(UInt8((word >> 24) & 0xFF))
    out.append(UInt8((word >> 16) & 0xFF))
    out.append(UInt8((word >> 8) & 0xFF))
    out.append(UInt8(word & 0xFF))
    word = h7
    out.append(UInt8((word >> 24) & 0xFF))
    out.append(UInt8((word >> 16) & 0xFF))
    out.append(UInt8((word >> 8) & 0xFF))
    out.append(UInt8(word & 0xFF))
    return out^
