"""Minimal 256-bit big integer helpers for P-256 ECDSA."""
from collections import List

fn u256_from_be(bytes: List[UInt8]) -> List[UInt64]:
    var limbs = List[UInt64]()
    # Pad/truncate to 32 bytes.
    var tmp = List[UInt8]()
    if len(bytes) >= 32:
        var start = len(bytes) - 32
        var i = 0
        while i < 32:
            tmp.append(bytes[start + i])
            i += 1
    else:
        var pad = 32 - len(bytes)
        var i = 0
        while i < pad:
            tmp.append(UInt8(0))
            i += 1
        for b in bytes:
            tmp.append(b)
    # Little-endian limbs (limb 0 is least significant).
    var limb = 0
    while limb < 4:
        var idx = 24 - limb * 8
        var v = UInt64(0)
        var j = 0
        while j < 8:
            v = (v << 8) | UInt64(tmp[idx + j])
            j += 1
        limbs.append(v)
        limb += 1
    return limbs^

fn u256_to_be(limbs: List[UInt64]) -> List[UInt8]:
    var out = List[UInt8]()
    var i = 3
    while i >= 0:
        var v = limbs[i]
        var j = 0
        while j < 8:
            var shift = (7 - j) * 8
            out.append(UInt8((v >> shift) & UInt64(0xff)))
            j += 1
        i -= 1
    return out^

fn trim_limbs(limbs: List[UInt64]) -> List[UInt64]:
    var out = limbs.copy()
    var i = len(out) - 1
    while i >= 0:
        if out[i] != UInt64(0):
            break
        _ = out.pop()
        i -= 1
    return out^

fn pad_limbs(limbs: List[UInt64], length: Int) -> List[UInt64]:
    var out = limbs.copy()
    while len(out) < length:
        out.append(UInt64(0))
    return out^

fn cmp_limbs(a: List[UInt64], b: List[UInt64]) -> Int:
    var aa = trim_limbs(a)
    var bb = trim_limbs(b)
    if len(aa) > len(bb):
        return 1
    if len(aa) < len(bb):
        return -1
    var i = len(aa) - 1
    while i >= 0:
        if aa[i] > bb[i]:
            return 1
        if aa[i] < bb[i]:
            return -1
        i -= 1
    return 0

fn add_limbs(a: List[UInt64], b: List[UInt64]) -> (List[UInt64], UInt64):
    var max_len = len(a)
    if len(b) > max_len:
        max_len = len(b)
    var aa = pad_limbs(a, max_len)
    var bb = pad_limbs(b, max_len)
    var out = List[UInt64]()
    var carry = UInt128(0)
    var i = 0
    while i < max_len:
        var sum = UInt128(aa[i]) + UInt128(bb[i]) + carry
        out.append(UInt64(sum & UInt128(0xffffffffffffffff)))
        carry = sum >> 64
        i += 1
    return (out^, UInt64(carry))

fn sub_limbs(a: List[UInt64], b: List[UInt64]) -> (List[UInt64], Bool):
    var max_len = len(a)
    var aa = pad_limbs(a, max_len)
    var bb = pad_limbs(b, max_len)
    var out = List[UInt64]()
    var borrow = UInt64(0)
    var i = 0
    while i < max_len:
        var ai = aa[i]
        var bi = bb[i]
        var tmp = UInt128(ai) - UInt128(bi) - UInt128(borrow)
        var val = UInt64(tmp & UInt128(0xffffffffffffffff))
        out.append(val)
        var bi_plus = UInt128(bi) + UInt128(borrow)
        if UInt128(ai) < bi_plus:
            borrow = UInt64(1)
        else:
            borrow = UInt64(0)
        i += 1
    return (out^, borrow == UInt64(1))

fn is_zero(limbs: List[UInt64]) -> Bool:
    for v in limbs:
        if v != UInt64(0):
            return False
    return True

fn is_even(limbs: List[UInt64]) -> Bool:
    if len(limbs) == 0:
        return True
    return (limbs[0] & UInt64(1)) == UInt64(0)

fn shr1(limbs: List[UInt64]) -> List[UInt64]:
    var out = limbs.copy()
    var i = len(out) - 1
    var carry = UInt64(0)
    while i >= 0:
        var v = out[i]
        out[i] = (v >> 1) | (carry << 63)
        carry = v & UInt64(1)
        i -= 1
    return out^

fn bit_length(limbs: List[UInt64]) -> Int:
    var i = len(limbs) - 1
    while i >= 0:
        if limbs[i] != UInt64(0):
            var v = limbs[i]
            var bits = 0
            while v != UInt64(0):
                v >>= 1
                bits += 1
            return i * 64 + bits
        i -= 1
    return 0

fn shl_bits(limbs: List[UInt64], shift: Int) -> List[UInt64]:
    if shift <= 0:
        return limbs.copy()
    var word_shift = shift // 64
    var bit_shift = shift % 64
    var out = List[UInt64]()
    var i = 0
    while i < word_shift:
        out.append(UInt64(0))
        i += 1
    var carry = UInt64(0)
    i = 0
    while i < len(limbs):
        var v = limbs[i]
        var combined = (UInt128(v) << bit_shift) | UInt128(carry)
        out.append(UInt64(combined & UInt128(0xffffffffffffffff)))
        carry = UInt64(combined >> 64)
        i += 1
    if carry != UInt64(0):
        out.append(carry)
    return out^

fn mul_u256(a: List[UInt64], b: List[UInt64]) -> List[UInt64]:
    var aa = pad_limbs(a, 4)
    var bb = pad_limbs(b, 4)
    var out = List[UInt64]()
    var i = 0
    while i < 8:
        out.append(UInt64(0))
        i += 1
    i = 0
    while i < 4:
        var carry = UInt128(0)
        var j = 0
        while j < 4:
            var idx = i + j
            var prod = UInt128(aa[i]) * UInt128(bb[j]) + UInt128(out[idx]) + carry
            out[idx] = UInt64(prod & UInt128(0xffffffffffffffff))
            carry = prod >> 64
            j += 1
        var idx2 = i + 4
        while carry != UInt128(0) and idx2 < len(out):
            var sum = UInt128(out[idx2]) + carry
            out[idx2] = UInt64(sum & UInt128(0xffffffffffffffff))
            carry = sum >> 64
            idx2 += 1
        i += 1
    return out^

fn mod_reduce(big: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    var rem = trim_limbs(big)
    var m = trim_limbs(mod)
    if cmp_limbs(rem, m) < 0:
        return pad_limbs(rem, 4)
    while cmp_limbs(rem, m) >= 0:
        var shift = bit_length(rem) - bit_length(m)
        var m_shift = shl_bits(m, shift)
        if cmp_limbs(rem, m_shift) < 0:
            shift -= 1
            m_shift = shl_bits(m, shift)
        var sub = sub_limbs(rem, m_shift)
        rem = trim_limbs(sub[0])
    return pad_limbs(rem, 4)

fn add_mod(a: List[UInt64], b: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    var sum = add_limbs(a, b)
    var out = pad_limbs(sum[0], 4)
    if sum[1] != UInt64(0) or cmp_limbs(out, mod) >= 0:
        out = sub_limbs(out, mod)[0].copy()
    return pad_limbs(out, 4)

fn sub_mod(a: List[UInt64], b: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    if cmp_limbs(a, b) >= 0:
        return pad_limbs(sub_limbs(a, b)[0], 4)
    var sum = add_limbs(a, mod)
    var out = sub_limbs(sum[0], b)[0].copy()
    return pad_limbs(out, 4)

fn mod_mul(a: List[UInt64], b: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    var prod = mul_u256(a, b)
    return mod_reduce(prod, mod)

fn get_bit(limbs: List[UInt64], idx: Int) -> UInt64:
    var limb = idx // 64
    var bit = idx % 64
    if limb >= len(limbs):
        return UInt64(0)
    return (limbs[limb] >> bit) & UInt64(1)

fn mod_pow(base: List[UInt64], exp: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    var result = List[UInt64]()
    result.append(UInt64(1))
    result.append(UInt64(0))
    result.append(UInt64(0))
    result.append(UInt64(0))
    var b = mod_reduce(base, mod)
    var bits = bit_length(exp)
    var i = 0
    while i < bits:
        if get_bit(exp, i) == UInt64(1):
            result = mod_mul(result, b, mod)
        b = mod_mul(b, b, mod)
        i += 1
    return pad_limbs(result, 4)

fn mod_inv(a: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    # Fermat: a^(mod-2) mod mod (mod must be prime).
    var two = List[UInt64]()
    two.append(UInt64(2))
    two.append(UInt64(0))
    two.append(UInt64(0))
    two.append(UInt64(0))
    var exp = sub_limbs(mod, two)[0].copy()
    return mod_pow(a, exp, mod)
