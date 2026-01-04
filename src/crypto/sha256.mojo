"""Pure Mojo SHA-256 implementation."""
from collections import List

fn mask32(x: Int) -> Int:
    return x & 0xffffffff

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
    k.append(0x428a2f98); k.append(0x71374491); k.append(0xb5c0fbcf); k.append(0xe9b5dba5)
    k.append(0x3956c25b); k.append(0x59f111f1); k.append(0x923f82a4); k.append(0xab1c5ed5)
    k.append(0xd807aa98); k.append(0x12835b01); k.append(0x243185be); k.append(0x550c7dc3)
    k.append(0x72be5d74); k.append(0x80deb1fe); k.append(0x9bdc06a7); k.append(0xc19bf174)
    k.append(0xe49b69c1); k.append(0xefbe4786); k.append(0x0fc19dc6); k.append(0x240ca1cc)
    k.append(0x2de92c6f); k.append(0x4a7484aa); k.append(0x5cb0a9dc); k.append(0x76f988da)
    k.append(0x983e5152); k.append(0xa831c66d); k.append(0xb00327c8); k.append(0xbf597fc7)
    k.append(0xc6e00bf3); k.append(0xd5a79147); k.append(0x06ca6351); k.append(0x14292967)
    k.append(0x27b70a85); k.append(0x2e1b2138); k.append(0x4d2c6dfc); k.append(0x53380d13)
    k.append(0x650a7354); k.append(0x766a0abb); k.append(0x81c2c92e); k.append(0x92722c85)
    k.append(0xa2bfe8a1); k.append(0xa81a664b); k.append(0xc24b8b70); k.append(0xc76c51a3)
    k.append(0xd192e819); k.append(0xd6990624); k.append(0xf40e3585); k.append(0x106aa070)
    k.append(0x19a4c116); k.append(0x1e376c08); k.append(0x2748774c); k.append(0x34b0bcb5)
    k.append(0x391c0cb3); k.append(0x4ed8aa4a); k.append(0x5b9cca4f); k.append(0x682e6ff3)
    k.append(0x748f82ee); k.append(0x78a5636f); k.append(0x84c87814); k.append(0x8cc70208)
    k.append(0x90befffa); k.append(0xa4506ceb); k.append(0xbef9a3f7); k.append(0xc67178f2)
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
        data.append(UInt8((bit_len >> shift) & UInt64(0xff)))
        i += 1

    var h0 = 0x6a09e667
    var h1 = 0xbb67ae85
    var h2 = 0x3c6ef372
    var h3 = 0xa54ff53a
    var h4 = 0x510e527f
    var h5 = 0x9b05688c
    var h6 = 0x1f83d9ab
    var h7 = 0x5be0cd19

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
    out.append(UInt8((word >> 24) & 0xff)); out.append(UInt8((word >> 16) & 0xff)); out.append(UInt8((word >> 8) & 0xff)); out.append(UInt8(word & 0xff))
    word = h1
    out.append(UInt8((word >> 24) & 0xff)); out.append(UInt8((word >> 16) & 0xff)); out.append(UInt8((word >> 8) & 0xff)); out.append(UInt8(word & 0xff))
    word = h2
    out.append(UInt8((word >> 24) & 0xff)); out.append(UInt8((word >> 16) & 0xff)); out.append(UInt8((word >> 8) & 0xff)); out.append(UInt8(word & 0xff))
    word = h3
    out.append(UInt8((word >> 24) & 0xff)); out.append(UInt8((word >> 16) & 0xff)); out.append(UInt8((word >> 8) & 0xff)); out.append(UInt8(word & 0xff))
    word = h4
    out.append(UInt8((word >> 24) & 0xff)); out.append(UInt8((word >> 16) & 0xff)); out.append(UInt8((word >> 8) & 0xff)); out.append(UInt8(word & 0xff))
    word = h5
    out.append(UInt8((word >> 24) & 0xff)); out.append(UInt8((word >> 16) & 0xff)); out.append(UInt8((word >> 8) & 0xff)); out.append(UInt8(word & 0xff))
    word = h6
    out.append(UInt8((word >> 24) & 0xff)); out.append(UInt8((word >> 16) & 0xff)); out.append(UInt8((word >> 8) & 0xff)); out.append(UInt8(word & 0xff))
    word = h7
    out.append(UInt8((word >> 24) & 0xff)); out.append(UInt8((word >> 16) & 0xff)); out.append(UInt8((word >> 8) & 0xff)); out.append(UInt8(word & 0xff))
    return out^
