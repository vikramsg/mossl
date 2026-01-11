"""Pure Mojo SHA-384 implementation."""
from collections import List

fn mask64(x: UInt128) -> UInt64:
    return UInt64(x & UInt128(0xFFFFFFFFFFFFFFFF))


fn rotr(x: UInt64, n: Int) -> UInt64:
    return (x >> n) | (x << (64 - n))


fn ch(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    return (x & y) ^ ((~x) & z)


fn maj(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    return (x & y) ^ (x & z) ^ (y & z)


fn big_sigma0(x: UInt64) -> UInt64:
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)


fn big_sigma1(x: UInt64) -> UInt64:
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)


fn small_sigma0(x: UInt64) -> UInt64:
    return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)


fn small_sigma1(x: UInt64) -> UInt64:
    return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)


fn k_constants() -> List[UInt64]:
    var k = List[UInt64]()
    k.append(0x428A2F98D728AE22)
    k.append(0x7137449123EF65CD)
    k.append(0xB5C0FBCFEC4D3B2F)
    k.append(0xE9B5DBA58189DBBC)
    k.append(0x3956C25BF348B538)
    k.append(0x59F111F1B605D019)
    k.append(0x923F82A4AF194F9B)
    k.append(0xAB1C5ED5DA6D8118)
    k.append(0xD807AA98A3030242)
    k.append(0x12835B0145706FBE)
    k.append(0x243185BE4EE4B28C)
    k.append(0x550C7DC3D5FFB4E2)
    k.append(0x72BE5D74F27B896F)
    k.append(0x80DEB1FE3B1696B1)
    k.append(0x9BDC06A725C71235)
    k.append(0xC19BF174CF692694)
    k.append(0xE49B69C19EF14AD2)
    k.append(0xEFBE4786384F25E3)
    k.append(0x0FC19DC68B8CD5B5)
    k.append(0x240CA1CC77AC9C65)
    k.append(0x2DE92C6F592B0275)
    k.append(0x4A7484AA6EA6E483)
    k.append(0x5CB0A9DCBD41FBD4)
    k.append(0x76F988DA831153B5)
    k.append(0x983E5152EE66DFAB)
    k.append(0xA831C66D2DB43210)
    k.append(0xB00327C898FB213F)
    k.append(0xBF597FC7BEEF0EE4)
    k.append(0xC6E00BF33DA88FC2)
    k.append(0xD5A79147930AA725)
    k.append(0x06CA6351E003826F)
    k.append(0x142929670A0E6E70)
    k.append(0x27B70A8546D22FFC)
    k.append(0x2E1B21385C26C926)
    k.append(0x4D2C6DFC5AC42AED)
    k.append(0x53380D139D95B3DF)
    k.append(0x650A73548BAF63DE)
    k.append(0x766A0ABB3C77B2A8)
    k.append(0x81C2C92E47EDAEE6)
    k.append(0x92722C851482353B)
    k.append(0xA2BFE8A14CF10364)
    k.append(0xA81A664BBC423001)
    k.append(0xC24B8B70D0F89791)
    k.append(0xC76C51A30654BE30)
    k.append(0xD192E819D6EF5218)
    k.append(0xD69906245565A910)
    k.append(0xF40E35855771202A)
    k.append(0x106AA07032BBD1B8)
    k.append(0x19A4C116B8D2D0C8)
    k.append(0x1E376C085141AB53)
    k.append(0x2748774CDF8EEB99)
    k.append(0x34B0BCB5E19B48A8)
    k.append(0x391C0CB3C5C95A63)
    k.append(0x4ED8AA4AE3418ACB)
    k.append(0x5B9CCA4F7763E373)
    k.append(0x682E6FF3D6B2B8A3)
    k.append(0x748F82EE5DEFB2FC)
    k.append(0x78A5636F43172F60)
    k.append(0x84C87814A1F0AB72)
    k.append(0x8CC702081A6439EC)
    k.append(0x90BEFFFA23631E28)
    k.append(0xA4506CEBDE82BDE9)
    k.append(0xBEF9A3F7B2C67915)
    k.append(0xC67178F2E372532B)
    k.append(0xCA273ECEEA26619C)
    k.append(0xD186B8C721C0C207)
    k.append(0xEADA7DD6CDE0EB1E)
    k.append(0xF57D4F7FEE6ED178)
    k.append(0x06F067AA72176FBA)
    k.append(0x0A637DC5A2C898A6)
    k.append(0x113F9804BEF90DAE)
    k.append(0x1B710B35131C471B)
    k.append(0x28DB77F523047D84)
    k.append(0x32CAAB7B40C72493)
    k.append(0x3C9EBE0A15C9BEBC)
    k.append(0x431D67C49C100D4C)
    k.append(0x4CC5D4BECB3E42B6)
    k.append(0x597F299CFC657E2A)
    k.append(0x5FCB6FAB3AD6FAEC)
    k.append(0x6C44198C4A475817)
    return k^


fn sha384_bytes(data_in: List[UInt8]) -> List[UInt8]:
    var data = List[UInt8]()
    for b in data_in:
        data.append(b)

    data.append(UInt8(0x80))
    while (len(data) % 128) != 112:
        data.append(UInt8(0))

    var bit_len = UInt128(len(data_in)) * UInt128(8)
    var high = UInt64(bit_len >> 64)
    var low = UInt64(bit_len & UInt128(0xFFFFFFFFFFFFFFFF))
    var i = 0
    while i < 8:
        var shift = (7 - i) * 8
        data.append(UInt8((high >> shift) & UInt64(0xFF)))
        i += 1
    i = 0
    while i < 8:
        var shift2 = (7 - i) * 8
        data.append(UInt8((low >> shift2) & UInt64(0xFF)))
        i += 1

    var h0 = UInt64(0xCBBB9D5DC1059ED8)
    var h1 = UInt64(0x629A292A367CD507)
    var h2 = UInt64(0x9159015A3070DD17)
    var h3 = UInt64(0x152FECD8F70E5939)
    var h4 = UInt64(0x67332667FFC00B31)
    var h5 = UInt64(0x8EB44A8768581511)
    var h6 = UInt64(0xDB0C2E0D64F98FA7)
    var h7 = UInt64(0x47B5481DBEFA4FA4)

    var k = k_constants()

    var chunk = 0
    while chunk < len(data):
        var w = List[UInt64]()
        var t = 0
        while t < 16:
            var base = chunk + t * 8
            var v = UInt64(0)
            var j = 0
            while j < 8:
                v = (v << 8) | UInt64(data[base + j])
                j += 1
            w.append(v)
            t += 1

        while t < 80:
            var s0 = small_sigma0(w[t - 15])
            var s1 = small_sigma1(w[t - 2])
            w.append(w[t - 16] + s0 + w[t - 7] + s1)
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
        while t < 80:
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
            t += 1

        h0 = h0 + a
        h1 = h1 + b
        h2 = h2 + c
        h3 = h3 + d
        h4 = h4 + e
        h5 = h5 + f
        h6 = h6 + g
        h7 = h7 + h

        chunk += 128

    var out = List[UInt8]()
    var words = List[UInt64]()
    words.append(h0)
    words.append(h1)
    words.append(h2)
    words.append(h3)
    words.append(h4)
    words.append(h5)
    for wv in words:
        var j = 0
        while j < 8:
            var shift3 = (7 - j) * 8
            out.append(UInt8((wv >> shift3) & UInt64(0xFF)))
            j += 1
    return out^
