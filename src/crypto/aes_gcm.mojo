"""AES-128 GCM implementation for TLS 1.3 record protection."""
from collections import List


fn xor_blocks(a: List[UInt8], b: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    var i = 0
    while i < len(a):
        out.append(UInt8(a[i] ^ b[i]))
        i += 1
    return out^


fn pad_block(block: List[UInt8]) -> List[UInt8]:
    if len(block) == 16:
        return block.copy()
    var out = List[UInt8]()
    for b in block:
        out.append(b)
    while len(out) < 16:
        out.append(UInt8(0))
    return out^


fn u128_from_be(block: List[UInt8]) -> UInt128:
    var out = UInt128(0)
    var i = 0
    while i < 16:
        out = (out << 8) | UInt128(block[i])
        i += 1
    return out


fn u128_to_be(value: UInt128) -> List[UInt8]:
    var out = List[UInt8]()
    var i = 0
    while i < 16:
        var shift = (15 - i) * 8
        out.append(UInt8((value >> shift) & UInt128(0xFF)))
        i += 1
    return out^


fn gf_mul(x: UInt128, y: UInt128) -> UInt128:
    var z = UInt128(0)
    var v = x
    var i = 0
    while i < 128:
        var bit = (y >> UInt128(127 - i)) & UInt128(1)
        if bit == UInt128(1):
            z ^= v
        var lsb = v & UInt128(1)
        v >>= 1
        if lsb == UInt128(1):
            v ^= UInt128(0xE1) << 120
        i += 1
    return z


fn ghash(
    h: List[UInt8], aad: List[UInt8], ciphertext: List[UInt8]
) -> List[UInt8]:
    var y = UInt128(0)
    var h128 = u128_from_be(h)

    var idx = 0
    while idx < len(aad):
        var block = List[UInt8]()
        var i = 0
        while i < 16 and idx + i < len(aad):
            block.append(aad[idx + i])
            i += 1
        y = gf_mul(y ^ u128_from_be(pad_block(block)), h128)
        idx += 16

    idx = 0
    while idx < len(ciphertext):
        var block2 = List[UInt8]()
        var j = 0
        while j < 16 and idx + j < len(ciphertext):
            block2.append(ciphertext[idx + j])
            j += 1
        y = gf_mul(y ^ u128_from_be(pad_block(block2)), h128)
        idx += 16

    var len_block = List[UInt8]()
    var aad_bits = UInt64(len(aad)) * UInt64(8)
    var ct_bits = UInt64(len(ciphertext)) * UInt64(8)
    var k = 0
    while k < 8:
        var shift_a = (7 - k) * 8
        len_block.append(UInt8((aad_bits >> shift_a) & UInt64(0xFF)))
        k += 1
    k = 0
    while k < 8:
        var shift_c = (7 - k) * 8
        len_block.append(UInt8((ct_bits >> shift_c) & UInt64(0xFF)))
        k += 1
    y = gf_mul(y ^ u128_from_be(len_block), h128)
    return u128_to_be(y)


fn inc32(counter: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    var i = 0
    while i < 16:
        out.append(counter[i])
        i += 1
    var v = UInt32(0)
    v |= UInt32(out[12]) << 24
    v |= UInt32(out[13]) << 16
    v |= UInt32(out[14]) << 8
    v |= UInt32(out[15])
    v = v + UInt32(1)
    out[12] = UInt8((v >> 24) & UInt32(0xFF))
    out[13] = UInt8((v >> 16) & UInt32(0xFF))
    out[14] = UInt8((v >> 8) & UInt32(0xFF))
    out[15] = UInt8(v & UInt32(0xFF))
    return out^


fn sbox() -> List[UInt8]:
    var s = List[UInt8]()
    s.append(UInt8(0x63))
    s.append(UInt8(0x7C))
    s.append(UInt8(0x77))
    s.append(UInt8(0x7B))
    s.append(UInt8(0xF2))
    s.append(UInt8(0x6B))
    s.append(UInt8(0x6F))
    s.append(UInt8(0xC5))
    s.append(UInt8(0x30))
    s.append(UInt8(0x01))
    s.append(UInt8(0x67))
    s.append(UInt8(0x2B))
    s.append(UInt8(0xFE))
    s.append(UInt8(0xD7))
    s.append(UInt8(0xAB))
    s.append(UInt8(0x76))
    s.append(UInt8(0xCA))
    s.append(UInt8(0x82))
    s.append(UInt8(0xC9))
    s.append(UInt8(0x7D))
    s.append(UInt8(0xFA))
    s.append(UInt8(0x59))
    s.append(UInt8(0x47))
    s.append(UInt8(0xF0))
    s.append(UInt8(0xAD))
    s.append(UInt8(0xD4))
    s.append(UInt8(0xA2))
    s.append(UInt8(0xAF))
    s.append(UInt8(0x9C))
    s.append(UInt8(0xA4))
    s.append(UInt8(0x72))
    s.append(UInt8(0xC0))
    s.append(UInt8(0xB7))
    s.append(UInt8(0xFD))
    s.append(UInt8(0x93))
    s.append(UInt8(0x26))
    s.append(UInt8(0x36))
    s.append(UInt8(0x3F))
    s.append(UInt8(0xF7))
    s.append(UInt8(0xCC))
    s.append(UInt8(0x34))
    s.append(UInt8(0xA5))
    s.append(UInt8(0xE5))
    s.append(UInt8(0xF1))
    s.append(UInt8(0x71))
    s.append(UInt8(0xD8))
    s.append(UInt8(0x31))
    s.append(UInt8(0x15))
    s.append(UInt8(0x04))
    s.append(UInt8(0xC7))
    s.append(UInt8(0x23))
    s.append(UInt8(0xC3))
    s.append(UInt8(0x18))
    s.append(UInt8(0x96))
    s.append(UInt8(0x05))
    s.append(UInt8(0x9A))
    s.append(UInt8(0x07))
    s.append(UInt8(0x12))
    s.append(UInt8(0x80))
    s.append(UInt8(0xE2))
    s.append(UInt8(0xEB))
    s.append(UInt8(0x27))
    s.append(UInt8(0xB2))
    s.append(UInt8(0x75))
    s.append(UInt8(0x09))
    s.append(UInt8(0x83))
    s.append(UInt8(0x2C))
    s.append(UInt8(0x1A))
    s.append(UInt8(0x1B))
    s.append(UInt8(0x6E))
    s.append(UInt8(0x5A))
    s.append(UInt8(0xA0))
    s.append(UInt8(0x52))
    s.append(UInt8(0x3B))
    s.append(UInt8(0xD6))
    s.append(UInt8(0xB3))
    s.append(UInt8(0x29))
    s.append(UInt8(0xE3))
    s.append(UInt8(0x2F))
    s.append(UInt8(0x84))
    s.append(UInt8(0x53))
    s.append(UInt8(0xD1))
    s.append(UInt8(0x00))
    s.append(UInt8(0xED))
    s.append(UInt8(0x20))
    s.append(UInt8(0xFC))
    s.append(UInt8(0xB1))
    s.append(UInt8(0x5B))
    s.append(UInt8(0x6A))
    s.append(UInt8(0xCB))
    s.append(UInt8(0xBE))
    s.append(UInt8(0x39))
    s.append(UInt8(0x4A))
    s.append(UInt8(0x4C))
    s.append(UInt8(0x58))
    s.append(UInt8(0xCF))
    s.append(UInt8(0xD0))
    s.append(UInt8(0xEF))
    s.append(UInt8(0xAA))
    s.append(UInt8(0xFB))
    s.append(UInt8(0x43))
    s.append(UInt8(0x4D))
    s.append(UInt8(0x33))
    s.append(UInt8(0x85))
    s.append(UInt8(0x45))
    s.append(UInt8(0xF9))
    s.append(UInt8(0x02))
    s.append(UInt8(0x7F))
    s.append(UInt8(0x50))
    s.append(UInt8(0x3C))
    s.append(UInt8(0x9F))
    s.append(UInt8(0xA8))
    s.append(UInt8(0x51))
    s.append(UInt8(0xA3))
    s.append(UInt8(0x40))
    s.append(UInt8(0x8F))
    s.append(UInt8(0x92))
    s.append(UInt8(0x9D))
    s.append(UInt8(0x38))
    s.append(UInt8(0xF5))
    s.append(UInt8(0xBC))
    s.append(UInt8(0xB6))
    s.append(UInt8(0xDA))
    s.append(UInt8(0x21))
    s.append(UInt8(0x10))
    s.append(UInt8(0xFF))
    s.append(UInt8(0xF3))
    s.append(UInt8(0xD2))
    s.append(UInt8(0xCD))
    s.append(UInt8(0x0C))
    s.append(UInt8(0x13))
    s.append(UInt8(0xEC))
    s.append(UInt8(0x5F))
    s.append(UInt8(0x97))
    s.append(UInt8(0x44))
    s.append(UInt8(0x17))
    s.append(UInt8(0xC4))
    s.append(UInt8(0xA7))
    s.append(UInt8(0x7E))
    s.append(UInt8(0x3D))
    s.append(UInt8(0x64))
    s.append(UInt8(0x5D))
    s.append(UInt8(0x19))
    s.append(UInt8(0x73))
    s.append(UInt8(0x60))
    s.append(UInt8(0x81))
    s.append(UInt8(0x4F))
    s.append(UInt8(0xDC))
    s.append(UInt8(0x22))
    s.append(UInt8(0x2A))
    s.append(UInt8(0x90))
    s.append(UInt8(0x88))
    s.append(UInt8(0x46))
    s.append(UInt8(0xEE))
    s.append(UInt8(0xB8))
    s.append(UInt8(0x14))
    s.append(UInt8(0xDE))
    s.append(UInt8(0x5E))
    s.append(UInt8(0x0B))
    s.append(UInt8(0xDB))
    s.append(UInt8(0xE0))
    s.append(UInt8(0x32))
    s.append(UInt8(0x3A))
    s.append(UInt8(0x0A))
    s.append(UInt8(0x49))
    s.append(UInt8(0x06))
    s.append(UInt8(0x24))
    s.append(UInt8(0x5C))
    s.append(UInt8(0xC2))
    s.append(UInt8(0xD3))
    s.append(UInt8(0xAC))
    s.append(UInt8(0x62))
    s.append(UInt8(0x91))
    s.append(UInt8(0x95))
    s.append(UInt8(0xE4))
    s.append(UInt8(0x79))
    s.append(UInt8(0xE7))
    s.append(UInt8(0xC8))
    s.append(UInt8(0x37))
    s.append(UInt8(0x6D))
    s.append(UInt8(0x8D))
    s.append(UInt8(0xD5))
    s.append(UInt8(0x4E))
    s.append(UInt8(0xA9))
    s.append(UInt8(0x6C))
    s.append(UInt8(0x56))
    s.append(UInt8(0xF4))
    s.append(UInt8(0xEA))
    s.append(UInt8(0x65))
    s.append(UInt8(0x7A))
    s.append(UInt8(0xAE))
    s.append(UInt8(0x08))
    s.append(UInt8(0xBA))
    s.append(UInt8(0x78))
    s.append(UInt8(0x25))
    s.append(UInt8(0x2E))
    s.append(UInt8(0x1C))
    s.append(UInt8(0xA6))
    s.append(UInt8(0xB4))
    s.append(UInt8(0xC6))
    s.append(UInt8(0xE8))
    s.append(UInt8(0xDD))
    s.append(UInt8(0x74))
    s.append(UInt8(0x1F))
    s.append(UInt8(0x4B))
    s.append(UInt8(0xBD))
    s.append(UInt8(0x8B))
    s.append(UInt8(0x8A))
    s.append(UInt8(0x70))
    s.append(UInt8(0x3E))
    s.append(UInt8(0xB5))
    s.append(UInt8(0x66))
    s.append(UInt8(0x48))
    s.append(UInt8(0x03))
    s.append(UInt8(0xF6))
    s.append(UInt8(0x0E))
    s.append(UInt8(0x61))
    s.append(UInt8(0x35))
    s.append(UInt8(0x57))
    s.append(UInt8(0xB9))
    s.append(UInt8(0x86))
    s.append(UInt8(0xC1))
    s.append(UInt8(0x1D))
    s.append(UInt8(0x9E))
    s.append(UInt8(0xE1))
    s.append(UInt8(0xF8))
    s.append(UInt8(0x98))
    s.append(UInt8(0x11))
    s.append(UInt8(0x69))
    s.append(UInt8(0xD9))
    s.append(UInt8(0x8E))
    s.append(UInt8(0x94))
    s.append(UInt8(0x9B))
    s.append(UInt8(0x1E))
    s.append(UInt8(0x87))
    s.append(UInt8(0xE9))
    s.append(UInt8(0xCE))
    s.append(UInt8(0x55))
    s.append(UInt8(0x28))
    s.append(UInt8(0xDF))
    s.append(UInt8(0x8C))
    s.append(UInt8(0xA1))
    s.append(UInt8(0x89))
    s.append(UInt8(0x0D))
    s.append(UInt8(0xBF))
    s.append(UInt8(0xE6))
    s.append(UInt8(0x42))
    s.append(UInt8(0x68))
    s.append(UInt8(0x41))
    s.append(UInt8(0x99))
    s.append(UInt8(0x2D))
    s.append(UInt8(0x0F))
    s.append(UInt8(0xB0))
    s.append(UInt8(0x54))
    s.append(UInt8(0xBB))
    s.append(UInt8(0x16))
    return s^


fn rcon() -> List[UInt8]:
    var r = List[UInt8]()
    r.append(UInt8(0x01))
    r.append(UInt8(0x02))
    r.append(UInt8(0x04))
    r.append(UInt8(0x08))
    r.append(UInt8(0x10))
    r.append(UInt8(0x20))
    r.append(UInt8(0x40))
    r.append(UInt8(0x80))
    r.append(UInt8(0x1B))
    r.append(UInt8(0x36))
    return r^


fn sub_bytes(state: List[UInt8]) -> List[UInt8]:
    var s = sbox()
    var out = List[UInt8]()
    for b in state:
        out.append(s[Int(b)])
    return out^


fn shift_rows(state: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    var i = 0
    while i < 16:
        out.append(UInt8(0))
        i += 1
    out[0] = state[0]
    out[4] = state[4]
    out[8] = state[8]
    out[12] = state[12]
    out[1] = state[5]
    out[5] = state[9]
    out[9] = state[13]
    out[13] = state[1]
    out[2] = state[10]
    out[6] = state[14]
    out[10] = state[2]
    out[14] = state[6]
    out[3] = state[15]
    out[7] = state[3]
    out[11] = state[7]
    out[15] = state[11]
    return out^


fn xtime(b: UInt8) -> UInt8:
    var x = UInt16(b) << 1
    if (b & UInt8(0x80)) != UInt8(0):
        x ^= UInt16(0x1B)
    return UInt8(x & UInt16(0xFF))


fn mix_columns(state: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    var i = 0
    while i < 16:
        out.append(UInt8(0))
        i += 1
    var c = 0
    while c < 4:
        var i0 = c * 4
        var a0 = state[i0]
        var a1 = state[i0 + 1]
        var a2 = state[i0 + 2]
        var a3 = state[i0 + 3]
        var t = UInt8(a0 ^ a1 ^ a2 ^ a3)
        var u = a0
        out[i0] = UInt8(a0 ^ t ^ xtime(UInt8(a0 ^ a1)))
        out[i0 + 1] = UInt8(a1 ^ t ^ xtime(UInt8(a1 ^ a2)))
        out[i0 + 2] = UInt8(a2 ^ t ^ xtime(UInt8(a2 ^ a3)))
        out[i0 + 3] = UInt8(a3 ^ t ^ xtime(UInt8(a3 ^ u)))
        c += 1
    return out^


fn add_round_key(state: List[UInt8], round_key: List[UInt8]) -> List[UInt8]:
    return xor_blocks(state, round_key)


fn key_expansion(key: List[UInt8]) -> List[UInt8]:
    var expanded = List[UInt8]()
    for b in key:
        expanded.append(b)
    var r = rcon()
    var i = 16
    var rcon_idx = 0
    while i < 176:
        var temp = List[UInt8]()
        temp.append(expanded[i - 4])
        temp.append(expanded[i - 3])
        temp.append(expanded[i - 2])
        temp.append(expanded[i - 1])
        if (i % 16) == 0:
            var t0 = temp[0]
            temp[0] = temp[1]
            temp[1] = temp[2]
            temp[2] = temp[3]
            temp[3] = t0
            var s = sbox()
            temp[0] = s[Int(temp[0])]
            temp[1] = s[Int(temp[1])]
            temp[2] = s[Int(temp[2])]
            temp[3] = s[Int(temp[3])]
            temp[0] = UInt8(temp[0] ^ r[rcon_idx])
            rcon_idx += 1
        var j = 0
        while j < 4:
            expanded.append(UInt8(expanded[i - 16] ^ temp[j]))
            i += 1
            j += 1
    return expanded^


fn aes_encrypt_block(key: List[UInt8], block: List[UInt8]) -> List[UInt8]:
    var round_keys = key_expansion(key)
    var state = add_round_key(block, round_keys[0:16])
    var round = 1
    while round < 10:
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round * 16 : round * 16 + 16])
        round += 1
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[160:176])
    return state^


fn gctr(key: List[UInt8], icb: List[UInt8], input: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    var counter = icb.copy()
    var idx = 0
    while idx < len(input):
        var block = List[UInt8]()
        var i = 0
        while i < 16:
            block.append(counter[i])
            i += 1
        var keystream = aes_encrypt_block(key, block)
        var j = 0
        while j < 16 and idx + j < len(input):
            out.append(UInt8(input[idx + j] ^ keystream[j]))
            j += 1
        counter = inc32(counter)
        idx += 16
    return out^


fn derive_j0(h: List[UInt8], iv: List[UInt8]) -> List[UInt8]:
    if len(iv) == 12:
        var out = List[UInt8]()
        for b in iv:
            out.append(b)
        out.append(UInt8(0))
        out.append(UInt8(0))
        out.append(UInt8(0))
        out.append(UInt8(1))
        return out^
    var s = ghash(h, iv, List[UInt8]())
    return s^


fn aes_gcm_seal(
    key: List[UInt8], iv: List[UInt8], aad: List[UInt8], plaintext: List[UInt8]
) -> (List[UInt8], List[UInt8]):
    var zero_block: List[UInt8] = [UInt8(0) for _ in range(16)]
    var h = aes_encrypt_block(key, zero_block)
    var j0 = derive_j0(h, iv)
    var ciphertext = gctr(key, inc32(j0), plaintext)
    var s = ghash(h, aad, ciphertext)
    var tag = gctr(key, j0, s)
    return (ciphertext^, tag^)


fn aes_gcm_open(
    key: List[UInt8],
    iv: List[UInt8],
    aad: List[UInt8],
    ciphertext: List[UInt8],
    tag: List[UInt8],
) -> (List[UInt8], Bool):
    var zero_block: List[UInt8] = [UInt8(0) for _ in range(16)]
    var h = aes_encrypt_block(key, zero_block)
    var j0 = derive_j0(h, iv)
    var s = ghash(h, aad, ciphertext)
    var expected = gctr(key, j0, s)
    if len(expected) != len(tag):
        return (List[UInt8](), False)
    var i = 0
    var same = True
    while i < len(tag):
        if expected[i] != tag[i]:
            same = False
        i += 1
    if not same:
        return (List[UInt8](), False)
    var plaintext = gctr(key, inc32(j0), ciphertext)
    return (plaintext^, True)
