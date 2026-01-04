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
        out.append(UInt8((value >> shift) & UInt128(0xff)))
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
            v ^= (UInt128(0xe1) << 120)
        i += 1
    return z

fn ghash(h: List[UInt8], aad: List[UInt8], ciphertext: List[UInt8]) -> List[UInt8]:
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
        len_block.append(UInt8((aad_bits >> shift_a) & UInt64(0xff)))
        k += 1
    k = 0
    while k < 8:
        var shift_c = (7 - k) * 8
        len_block.append(UInt8((ct_bits >> shift_c) & UInt64(0xff)))
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
    out[12] = UInt8((v >> 24) & UInt32(0xff))
    out[13] = UInt8((v >> 16) & UInt32(0xff))
    out[14] = UInt8((v >> 8) & UInt32(0xff))
    out[15] = UInt8(v & UInt32(0xff))
    return out^

fn sbox() -> List[UInt8]:
    var s = List[UInt8]()
    s.append(UInt8(0x63)); s.append(UInt8(0x7c)); s.append(UInt8(0x77)); s.append(UInt8(0x7b))
    s.append(UInt8(0xf2)); s.append(UInt8(0x6b)); s.append(UInt8(0x6f)); s.append(UInt8(0xc5))
    s.append(UInt8(0x30)); s.append(UInt8(0x01)); s.append(UInt8(0x67)); s.append(UInt8(0x2b))
    s.append(UInt8(0xfe)); s.append(UInt8(0xd7)); s.append(UInt8(0xab)); s.append(UInt8(0x76))
    s.append(UInt8(0xca)); s.append(UInt8(0x82)); s.append(UInt8(0xc9)); s.append(UInt8(0x7d))
    s.append(UInt8(0xfa)); s.append(UInt8(0x59)); s.append(UInt8(0x47)); s.append(UInt8(0xf0))
    s.append(UInt8(0xad)); s.append(UInt8(0xd4)); s.append(UInt8(0xa2)); s.append(UInt8(0xaf))
    s.append(UInt8(0x9c)); s.append(UInt8(0xa4)); s.append(UInt8(0x72)); s.append(UInt8(0xc0))
    s.append(UInt8(0xb7)); s.append(UInt8(0xfd)); s.append(UInt8(0x93)); s.append(UInt8(0x26))
    s.append(UInt8(0x36)); s.append(UInt8(0x3f)); s.append(UInt8(0xf7)); s.append(UInt8(0xcc))
    s.append(UInt8(0x34)); s.append(UInt8(0xa5)); s.append(UInt8(0xe5)); s.append(UInt8(0xf1))
    s.append(UInt8(0x71)); s.append(UInt8(0xd8)); s.append(UInt8(0x31)); s.append(UInt8(0x15))
    s.append(UInt8(0x04)); s.append(UInt8(0xc7)); s.append(UInt8(0x23)); s.append(UInt8(0xc3))
    s.append(UInt8(0x18)); s.append(UInt8(0x96)); s.append(UInt8(0x05)); s.append(UInt8(0x9a))
    s.append(UInt8(0x07)); s.append(UInt8(0x12)); s.append(UInt8(0x80)); s.append(UInt8(0xe2))
    s.append(UInt8(0xeb)); s.append(UInt8(0x27)); s.append(UInt8(0xb2)); s.append(UInt8(0x75))
    s.append(UInt8(0x09)); s.append(UInt8(0x83)); s.append(UInt8(0x2c)); s.append(UInt8(0x1a))
    s.append(UInt8(0x1b)); s.append(UInt8(0x6e)); s.append(UInt8(0x5a)); s.append(UInt8(0xa0))
    s.append(UInt8(0x52)); s.append(UInt8(0x3b)); s.append(UInt8(0xd6)); s.append(UInt8(0xb3))
    s.append(UInt8(0x29)); s.append(UInt8(0xe3)); s.append(UInt8(0x2f)); s.append(UInt8(0x84))
    s.append(UInt8(0x53)); s.append(UInt8(0xd1)); s.append(UInt8(0x00)); s.append(UInt8(0xed))
    s.append(UInt8(0x20)); s.append(UInt8(0xfc)); s.append(UInt8(0xb1)); s.append(UInt8(0x5b))
    s.append(UInt8(0x6a)); s.append(UInt8(0xcb)); s.append(UInt8(0xbe)); s.append(UInt8(0x39))
    s.append(UInt8(0x4a)); s.append(UInt8(0x4c)); s.append(UInt8(0x58)); s.append(UInt8(0xcf))
    s.append(UInt8(0xd0)); s.append(UInt8(0xef)); s.append(UInt8(0xaa)); s.append(UInt8(0xfb))
    s.append(UInt8(0x43)); s.append(UInt8(0x4d)); s.append(UInt8(0x33)); s.append(UInt8(0x85))
    s.append(UInt8(0x45)); s.append(UInt8(0xf9)); s.append(UInt8(0x02)); s.append(UInt8(0x7f))
    s.append(UInt8(0x50)); s.append(UInt8(0x3c)); s.append(UInt8(0x9f)); s.append(UInt8(0xa8))
    s.append(UInt8(0x51)); s.append(UInt8(0xa3)); s.append(UInt8(0x40)); s.append(UInt8(0x8f))
    s.append(UInt8(0x92)); s.append(UInt8(0x9d)); s.append(UInt8(0x38)); s.append(UInt8(0xf5))
    s.append(UInt8(0xbc)); s.append(UInt8(0xb6)); s.append(UInt8(0xda)); s.append(UInt8(0x21))
    s.append(UInt8(0x10)); s.append(UInt8(0xff)); s.append(UInt8(0xf3)); s.append(UInt8(0xd2))
    s.append(UInt8(0xcd)); s.append(UInt8(0x0c)); s.append(UInt8(0x13)); s.append(UInt8(0xec))
    s.append(UInt8(0x5f)); s.append(UInt8(0x97)); s.append(UInt8(0x44)); s.append(UInt8(0x17))
    s.append(UInt8(0xc4)); s.append(UInt8(0xa7)); s.append(UInt8(0x7e)); s.append(UInt8(0x3d))
    s.append(UInt8(0x64)); s.append(UInt8(0x5d)); s.append(UInt8(0x19)); s.append(UInt8(0x73))
    s.append(UInt8(0x60)); s.append(UInt8(0x81)); s.append(UInt8(0x4f)); s.append(UInt8(0xdc))
    s.append(UInt8(0x22)); s.append(UInt8(0x2a)); s.append(UInt8(0x90)); s.append(UInt8(0x88))
    s.append(UInt8(0x46)); s.append(UInt8(0xee)); s.append(UInt8(0xb8)); s.append(UInt8(0x14))
    s.append(UInt8(0xde)); s.append(UInt8(0x5e)); s.append(UInt8(0x0b)); s.append(UInt8(0xdb))
    s.append(UInt8(0xe0)); s.append(UInt8(0x32)); s.append(UInt8(0x3a)); s.append(UInt8(0x0a))
    s.append(UInt8(0x49)); s.append(UInt8(0x06)); s.append(UInt8(0x24)); s.append(UInt8(0x5c))
    s.append(UInt8(0xc2)); s.append(UInt8(0xd3)); s.append(UInt8(0xac)); s.append(UInt8(0x62))
    s.append(UInt8(0x91)); s.append(UInt8(0x95)); s.append(UInt8(0xe4)); s.append(UInt8(0x79))
    s.append(UInt8(0xe7)); s.append(UInt8(0xc8)); s.append(UInt8(0x37)); s.append(UInt8(0x6d))
    s.append(UInt8(0x8d)); s.append(UInt8(0xd5)); s.append(UInt8(0x4e)); s.append(UInt8(0xa9))
    s.append(UInt8(0x6c)); s.append(UInt8(0x56)); s.append(UInt8(0xf4)); s.append(UInt8(0xea))
    s.append(UInt8(0x65)); s.append(UInt8(0x7a)); s.append(UInt8(0xae)); s.append(UInt8(0x08))
    s.append(UInt8(0xba)); s.append(UInt8(0x78)); s.append(UInt8(0x25)); s.append(UInt8(0x2e))
    s.append(UInt8(0x1c)); s.append(UInt8(0xa6)); s.append(UInt8(0xb4)); s.append(UInt8(0xc6))
    s.append(UInt8(0xe8)); s.append(UInt8(0xdd)); s.append(UInt8(0x74)); s.append(UInt8(0x1f))
    s.append(UInt8(0x4b)); s.append(UInt8(0xbd)); s.append(UInt8(0x8b)); s.append(UInt8(0x8a))
    s.append(UInt8(0x70)); s.append(UInt8(0x3e)); s.append(UInt8(0xb5)); s.append(UInt8(0x66))
    s.append(UInt8(0x48)); s.append(UInt8(0x03)); s.append(UInt8(0xf6)); s.append(UInt8(0x0e))
    s.append(UInt8(0x61)); s.append(UInt8(0x35)); s.append(UInt8(0x57)); s.append(UInt8(0xb9))
    s.append(UInt8(0x86)); s.append(UInt8(0xc1)); s.append(UInt8(0x1d)); s.append(UInt8(0x9e))
    s.append(UInt8(0xe1)); s.append(UInt8(0xf8)); s.append(UInt8(0x98)); s.append(UInt8(0x11))
    s.append(UInt8(0x69)); s.append(UInt8(0xd9)); s.append(UInt8(0x8e)); s.append(UInt8(0x94))
    s.append(UInt8(0x9b)); s.append(UInt8(0x1e)); s.append(UInt8(0x87)); s.append(UInt8(0xe9))
    s.append(UInt8(0xce)); s.append(UInt8(0x55)); s.append(UInt8(0x28)); s.append(UInt8(0xdf))
    s.append(UInt8(0x8c)); s.append(UInt8(0xa1)); s.append(UInt8(0x89)); s.append(UInt8(0x0d))
    s.append(UInt8(0xbf)); s.append(UInt8(0xe6)); s.append(UInt8(0x42)); s.append(UInt8(0x68))
    s.append(UInt8(0x41)); s.append(UInt8(0x99)); s.append(UInt8(0x2d)); s.append(UInt8(0x0f))
    s.append(UInt8(0xb0)); s.append(UInt8(0x54)); s.append(UInt8(0xbb)); s.append(UInt8(0x16))
    return s^

fn rcon() -> List[UInt8]:
    var r = List[UInt8]()
    r.append(UInt8(0x01)); r.append(UInt8(0x02)); r.append(UInt8(0x04)); r.append(UInt8(0x08))
    r.append(UInt8(0x10)); r.append(UInt8(0x20)); r.append(UInt8(0x40)); r.append(UInt8(0x80))
    r.append(UInt8(0x1b)); r.append(UInt8(0x36))
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
    out[0] = state[0]; out[4] = state[4]; out[8] = state[8]; out[12] = state[12]
    out[1] = state[5]; out[5] = state[9]; out[9] = state[13]; out[13] = state[1]
    out[2] = state[10]; out[6] = state[14]; out[10] = state[2]; out[14] = state[6]
    out[3] = state[15]; out[7] = state[3]; out[11] = state[7]; out[15] = state[11]
    return out^

fn xtime(b: UInt8) -> UInt8:
    var x = UInt16(b) << 1
    if (b & UInt8(0x80)) != UInt8(0):
        x ^= UInt16(0x1b)
    return UInt8(x & UInt16(0xff))

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
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t0
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
        state = add_round_key(state, round_keys[round * 16: round * 16 + 16])
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
        out.append(UInt8(0)); out.append(UInt8(0)); out.append(UInt8(0)); out.append(UInt8(1))
        return out^
    var s = ghash(h, iv, List[UInt8]())
    return s^

fn aes_gcm_seal(key: List[UInt8], iv: List[UInt8], aad: List[UInt8], plaintext: List[UInt8]) -> (List[UInt8], List[UInt8]):
    var zero_block: List[UInt8] = [UInt8(0) for _ in range(16)]
    var h = aes_encrypt_block(key, zero_block)
    var j0 = derive_j0(h, iv)
    var ciphertext = gctr(key, inc32(j0), plaintext)
    var s = ghash(h, aad, ciphertext)
    var tag = gctr(key, j0, s)
    return (ciphertext^, tag^)
