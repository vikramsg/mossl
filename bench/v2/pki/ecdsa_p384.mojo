from collections import List, InlineArray

from memory import UnsafePointer
from pki.asn1 import DerReader, read_sequence_reader, read_integer_bytes

from crypto.bytes import hex_to_bytes

# ==============================================================================
# U384 Arithmetic (6-limb, 384-bit)
# ==============================================================================


@register_passable("trivial")
struct U384(Copyable, Movable):
    var l0: UInt64
    var l1: UInt64
    var l2: UInt64
    var l3: UInt64
    var l4: UInt64
    var l5: UInt64

    fn __init__(out self, val: UInt64):
        self.l0 = val
        self.l1 = 0
        self.l2 = 0
        self.l3 = 0
        self.l4 = 0
        self.l5 = 0

    fn __init__(
        out self,
        l0: UInt64,
        l1: UInt64,
        l2: UInt64,
        l3: UInt64,
        l4: UInt64,
        l5: UInt64,
    ):
        self.l0 = l0
        self.l1 = l1
        self.l2 = l2
        self.l3 = l3
        self.l4 = l4
        self.l5 = l5

    @staticmethod
    fn from_bytes(bytes: List[UInt8]) -> U384:
        # Expects Big Endian bytes.
        # If len < 48, pad with zeros at the front.
        # If len > 48, take the last 48 bytes (or should we error? crypto usually demands exact sizes).
        # For simplicity assuming correct sizing or padding.
        var padded = List[UInt8]()
        var b_len = len(bytes)
        if b_len < 48:
            for _ in range(48 - b_len):
                padded.append(0)
            for i in range(b_len):
                padded.append(bytes[i])
        else:
            # Take last 48 bytes if longer (e.g. from BigInt bytes that might have extra zero)
            var start = b_len - 48
            for i in range(48):
                padded.append(bytes[start + i])

        # Now parse 8 bytes at a time into UInt64 (Big Endian)
        # padded[0..8] -> l5 (most significant)
        # ...
        # padded[40..48] -> l0 (least significant)

        var limbs = InlineArray[UInt64, 6](0)
        for i in range(6):
            var val = UInt64(0)
            for j in range(8):
                val = (val << 8) | UInt64(padded[(5 - i) * 8 + j])
            limbs[i] = val

        return U384(limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5])

    @always_inline
    fn is_zero(self) -> Bool:
        return (self.l0 | self.l1 | self.l2 | self.l3 | self.l4 | self.l5) == 0

    @staticmethod
    fn p384_p() -> U384:
        return U384(
            0x00000000FFFFFFFF,
            0xFFFFFFFF00000000,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        )

    @staticmethod
    fn p384_n() -> U384:
        return U384(
            0xECEC196ACCC52973,
            0x581A0DB248B0A77A,
            0xC7634D81F4372DDF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        )


@always_inline
fn u384_cmp(a: U384, b: U384) -> Int:
    if a.l5 > b.l5:
        return 1
    if a.l5 < b.l5:
        return -1
    if a.l4 > b.l4:
        return 1
    if a.l4 < b.l4:
        return -1
    if a.l3 > b.l3:
        return 1
    if a.l3 < b.l3:
        return -1
    if a.l2 > b.l2:
        return 1
    if a.l2 < b.l2:
        return -1
    if a.l1 > b.l1:
        return 1
    if a.l1 < b.l1:
        return -1
    if a.l0 > b.l0:
        return 1
    if a.l0 < b.l0:
        return -1
    return 0


@always_inline
fn u384_sub_limbs(a: U384, b: U384) -> U384:
    var borrow = Int128(0)

    var d0 = Int128(a.l0) - Int128(b.l0) - borrow
    var l0 = UInt64(d0 & 0xFFFFFFFFFFFFFFFF)
    borrow = 1 if d0 < 0 else 0

    var d1 = Int128(a.l1) - Int128(b.l1) - borrow
    var l1 = UInt64(d1 & 0xFFFFFFFFFFFFFFFF)
    borrow = 1 if d1 < 0 else 0

    var d2 = Int128(a.l2) - Int128(b.l2) - borrow
    var l2 = UInt64(d2 & 0xFFFFFFFFFFFFFFFF)
    borrow = 1 if d2 < 0 else 0

    var d3 = Int128(a.l3) - Int128(b.l3) - borrow
    var l3 = UInt64(d3 & 0xFFFFFFFFFFFFFFFF)
    borrow = 1 if d3 < 0 else 0

    var d4 = Int128(a.l4) - Int128(b.l4) - borrow
    var l4 = UInt64(d4 & 0xFFFFFFFFFFFFFFFF)
    borrow = 1 if d4 < 0 else 0

    var d5 = Int128(a.l5) - Int128(b.l5) - borrow
    var l5 = UInt64(d5 & 0xFFFFFFFFFFFFFFFF)

    return U384(l0, l1, l2, l3, l4, l5)


@always_inline
fn u384_add_mod(a: U384, b: U384, m: U384) -> U384:
    var s0 = UInt128(a.l0) + UInt128(b.l0)
    var l0 = UInt64(s0)
    var carry = s0 >> 64

    var s1 = UInt128(a.l1) + UInt128(b.l1) + carry
    var l1 = UInt64(s1)
    carry = s1 >> 64

    var s2 = UInt128(a.l2) + UInt128(b.l2) + carry
    var l2 = UInt64(s2)
    carry = s2 >> 64

    var s3 = UInt128(a.l3) + UInt128(b.l3) + carry
    var l3 = UInt64(s3)
    carry = s3 >> 64

    var s4 = UInt128(a.l4) + UInt128(b.l4) + carry
    var l4 = UInt64(s4)
    carry = s4 >> 64

    var s5 = UInt128(a.l5) + UInt128(b.l5) + carry
    var l5 = UInt64(s5)

    var sum = U384(l0, l1, l2, l3, l4, l5)
    if (s5 >> 64) > 0 or u384_cmp(sum, m) >= 0:
        return u384_sub_limbs(sum, m)
    return sum


@always_inline
fn u384_sub_mod(a: U384, b: U384, m: U384) -> U384:
    if u384_cmp(a, b) >= 0:
        return u384_sub_limbs(a, b)
    var diff = u384_sub_limbs(a, b)
    # Add modulus
    var s0 = UInt128(diff.l0) + UInt128(m.l0)
    var l0 = UInt64(s0)
    var carry = s0 >> 64

    var s1 = UInt128(diff.l1) + UInt128(m.l1) + carry
    var l1 = UInt64(s1)
    carry = s1 >> 64

    var s2 = UInt128(diff.l2) + UInt128(m.l2) + carry
    var l2 = UInt64(s2)
    carry = s2 >> 64

    var s3 = UInt128(diff.l3) + UInt128(m.l3) + carry
    var l3 = UInt64(s3)
    carry = s3 >> 64

    var s4 = UInt128(diff.l4) + UInt128(m.l4) + carry
    var l4 = UInt64(s4)
    carry = s4 >> 64

    var s5 = UInt128(diff.l5) + UInt128(m.l5) + carry
    var l5 = UInt64(s5)

    return U384(l0, l1, l2, l3, l4, l5)


fn mont_mul(a: U384, b: U384, m: U384, n0_inv: UInt64) -> U384:
    # Stack allocate temporary array for product
    # Size 14 to hold 2*N + overflow
    var t = UnsafePointer[UInt64].alloc(14)
    for i in range(14):
        t[i] = 0

    # 1. T = A * B

    # i = 0
    var carry = UInt128(0)
    var val = UInt128(t[0]) + UInt128(a.l0) * UInt128(b.l0) + carry
    t[0] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[1]) + UInt128(a.l0) * UInt128(b.l1) + carry
    t[1] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[2]) + UInt128(a.l0) * UInt128(b.l2) + carry
    t[2] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[3]) + UInt128(a.l0) * UInt128(b.l3) + carry
    t[3] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[4]) + UInt128(a.l0) * UInt128(b.l4) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(a.l0) * UInt128(b.l5) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    t[6] = UInt64(carry)

    # i = 1
    carry = 0
    val = UInt128(t[1]) + UInt128(a.l1) * UInt128(b.l0) + carry
    t[1] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[2]) + UInt128(a.l1) * UInt128(b.l1) + carry
    t[2] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[3]) + UInt128(a.l1) * UInt128(b.l2) + carry
    t[3] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[4]) + UInt128(a.l1) * UInt128(b.l3) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(a.l1) * UInt128(b.l4) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(a.l1) * UInt128(b.l5) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    t[7] = UInt64(carry)

    # i = 2
    carry = 0
    val = UInt128(t[2]) + UInt128(a.l2) * UInt128(b.l0) + carry
    t[2] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[3]) + UInt128(a.l2) * UInt128(b.l1) + carry
    t[3] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[4]) + UInt128(a.l2) * UInt128(b.l2) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(a.l2) * UInt128(b.l3) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(a.l2) * UInt128(b.l4) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[7]) + UInt128(a.l2) * UInt128(b.l5) + carry
    t[7] = UInt64(val)
    carry = val >> 64
    t[8] = UInt64(carry)

    # i = 3
    carry = 0
    val = UInt128(t[3]) + UInt128(a.l3) * UInt128(b.l0) + carry
    t[3] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[4]) + UInt128(a.l3) * UInt128(b.l1) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(a.l3) * UInt128(b.l2) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(a.l3) * UInt128(b.l3) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[7]) + UInt128(a.l3) * UInt128(b.l4) + carry
    t[7] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[8]) + UInt128(a.l3) * UInt128(b.l5) + carry
    t[8] = UInt64(val)
    carry = val >> 64
    t[9] = UInt64(carry)

    # i = 4
    carry = 0
    val = UInt128(t[4]) + UInt128(a.l4) * UInt128(b.l0) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(a.l4) * UInt128(b.l1) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(a.l4) * UInt128(b.l2) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[7]) + UInt128(a.l4) * UInt128(b.l3) + carry
    t[7] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[8]) + UInt128(a.l4) * UInt128(b.l4) + carry
    t[8] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[9]) + UInt128(a.l4) * UInt128(b.l5) + carry
    t[9] = UInt64(val)
    carry = val >> 64
    t[10] = UInt64(carry)

    # i = 5
    carry = 0
    val = UInt128(t[5]) + UInt128(a.l5) * UInt128(b.l0) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(a.l5) * UInt128(b.l1) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[7]) + UInt128(a.l5) * UInt128(b.l2) + carry
    t[7] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[8]) + UInt128(a.l5) * UInt128(b.l3) + carry
    t[8] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[9]) + UInt128(a.l5) * UInt128(b.l4) + carry
    t[9] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[10]) + UInt128(a.l5) * UInt128(b.l5) + carry
    t[10] = UInt64(val)
    carry = val >> 64
    t[11] = UInt64(carry)

    # 2. Reduction (also unrolled)

    # i = 0
    var u = UInt64((UInt128(t[0]) * UInt128(n0_inv)) & 0xFFFFFFFFFFFFFFFF)
    carry = 0
    val = UInt128(t[0]) + UInt128(u) * UInt128(m.l0) + carry
    t[0] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[1]) + UInt128(u) * UInt128(m.l1) + carry
    t[1] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[2]) + UInt128(u) * UInt128(m.l2) + carry
    t[2] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[3]) + UInt128(u) * UInt128(m.l3) + carry
    t[3] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[4]) + UInt128(u) * UInt128(m.l4) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(u) * UInt128(m.l5) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + carry
    t[6] = UInt64(val)
    carry = val >> 64

    var k = 7
    while carry > 0:
        val = UInt128(t[k]) + carry
        t[k] = UInt64(val)
        carry = val >> 64
        k += 1

    # i = 1
    u = UInt64((UInt128(t[1]) * UInt128(n0_inv)) & 0xFFFFFFFFFFFFFFFF)
    carry = 0
    val = UInt128(t[1]) + UInt128(u) * UInt128(m.l0) + carry
    t[1] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[2]) + UInt128(u) * UInt128(m.l1) + carry
    t[2] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[3]) + UInt128(u) * UInt128(m.l2) + carry
    t[3] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[4]) + UInt128(u) * UInt128(m.l3) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(u) * UInt128(m.l4) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(u) * UInt128(m.l5) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[7]) + carry
    t[7] = UInt64(val)
    carry = val >> 64

    k = 8
    while carry > 0:
        val = UInt128(t[k]) + carry
        t[k] = UInt64(val)
        carry = val >> 64
        k += 1

    # i = 2
    u = UInt64((UInt128(t[2]) * UInt128(n0_inv)) & 0xFFFFFFFFFFFFFFFF)
    carry = 0
    val = UInt128(t[2]) + UInt128(u) * UInt128(m.l0) + carry
    t[2] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[3]) + UInt128(u) * UInt128(m.l1) + carry
    t[3] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[4]) + UInt128(u) * UInt128(m.l2) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(u) * UInt128(m.l3) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(u) * UInt128(m.l4) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[7]) + UInt128(u) * UInt128(m.l5) + carry
    t[7] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[8]) + carry
    t[8] = UInt64(val)
    carry = val >> 64

    k = 9
    while carry > 0:
        val = UInt128(t[k]) + carry
        t[k] = UInt64(val)
        carry = val >> 64
        k += 1

    # i = 3
    u = UInt64((UInt128(t[3]) * UInt128(n0_inv)) & 0xFFFFFFFFFFFFFFFF)
    carry = 0
    val = UInt128(t[3]) + UInt128(u) * UInt128(m.l0) + carry
    t[3] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[4]) + UInt128(u) * UInt128(m.l1) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(u) * UInt128(m.l2) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(u) * UInt128(m.l3) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[7]) + UInt128(u) * UInt128(m.l4) + carry
    t[7] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[8]) + UInt128(u) * UInt128(m.l5) + carry
    t[8] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[9]) + carry
    t[9] = UInt64(val)
    carry = val >> 64

    k = 10
    while carry > 0:
        val = UInt128(t[k]) + carry
        t[k] = UInt64(val)
        carry = val >> 64
        k += 1

    # i = 4
    u = UInt64((UInt128(t[4]) * UInt128(n0_inv)) & 0xFFFFFFFFFFFFFFFF)
    carry = 0
    val = UInt128(t[4]) + UInt128(u) * UInt128(m.l0) + carry
    t[4] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[5]) + UInt128(u) * UInt128(m.l1) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(u) * UInt128(m.l2) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[7]) + UInt128(u) * UInt128(m.l3) + carry
    t[7] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[8]) + UInt128(u) * UInt128(m.l4) + carry
    t[8] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[9]) + UInt128(u) * UInt128(m.l5) + carry
    t[9] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[10]) + carry
    t[10] = UInt64(val)
    carry = val >> 64

    k = 11
    while carry > 0:
        val = UInt128(t[k]) + carry
        t[k] = UInt64(val)
        carry = val >> 64
        k += 1

    # i = 5
    u = UInt64((UInt128(t[5]) * UInt128(n0_inv)) & 0xFFFFFFFFFFFFFFFF)
    carry = 0
    val = UInt128(t[5]) + UInt128(u) * UInt128(m.l0) + carry
    t[5] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[6]) + UInt128(u) * UInt128(m.l1) + carry
    t[6] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[7]) + UInt128(u) * UInt128(m.l2) + carry
    t[7] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[8]) + UInt128(u) * UInt128(m.l3) + carry
    t[8] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[9]) + UInt128(u) * UInt128(m.l4) + carry
    t[9] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[10]) + UInt128(u) * UInt128(m.l5) + carry
    t[10] = UInt64(val)
    carry = val >> 64
    val = UInt128(t[11]) + carry
    t[11] = UInt64(val)
    carry = val >> 64

    k = 12
    while carry > 0:
        val = UInt128(t[k]) + carry
        t[k] = UInt64(val)
        carry = val >> 64
        k += 1

    var res = U384(t[6], t[7], t[8], t[9], t[10], t[11])
    var overflow = t[12]
    t.free()

    if overflow > 0 or u384_cmp(res, m) >= 0:
        return u384_sub_limbs(res, m)
    return res


fn mont_sqr(a: U384, m: U384, n0_inv: UInt64) -> U384:
    return mont_mul(a, a, m, n0_inv)


fn mont_pow(
    base: U384, exp: U384, m: U384, n0_inv: UInt64, one_mont: U384
) -> U384:
    var res = one_mont
    var b = base

    var limbs = InlineArray[UInt64, 6](0)
    limbs[0] = exp.l0
    limbs[1] = exp.l1
    limbs[2] = exp.l2
    limbs[3] = exp.l3
    limbs[4] = exp.l4
    limbs[5] = exp.l5

    for i in range(384):
        var limb_idx = i // 64
        var bit_idx = i % 64
        var bit = (limbs[limb_idx] >> bit_idx) & 1

        if bit == 1:
            res = mont_mul(res, b, m, n0_inv)
        b = mont_sqr(b, m, n0_inv)

    return res


# ==============================================================================
# Contexts
# ==============================================================================


struct P384Context(Movable):
    var m: U384
    var n0_inv: UInt64
    var r2: U384
    var one: U384

    fn __init__(out self, m: U384, n0_inv: UInt64, r2: U384, one: U384):
        self.m = m
        self.n0_inv = n0_inv
        self.r2 = r2
        self.one = one


struct ScalarContext(Movable):
    var m: U384
    var n0_inv: UInt64
    var r2: U384
    var one: U384

    fn __init__(out self, m: U384, n0_inv: UInt64, r2: U384, one: U384):
        self.m = m
        self.n0_inv = n0_inv
        self.r2 = r2
        self.one = one


fn u384_inv_mod(
    a: U384, m: U384, n0_inv: UInt64, one_mont: U384, r2: U384
) -> U384:
    var two = U384(2)
    var exp = u384_sub_limbs(m, two)
    return mont_pow(a, exp, m, n0_inv, one_mont)


# ==============================================================================
# Point Arithmetic
# ==============================================================================


@register_passable("trivial")
struct PointJac(Copyable, Movable):
    var x: U384
    var y: U384
    var z: U384

    fn __init__(out self, x: U384, y: U384, z: U384):
        self.x = x
        self.y = y
        self.z = z

    fn is_infinity(self) -> Bool:
        return self.z.is_zero()


fn from_affine(x: U384, y: U384, ctx: P384Context) -> PointJac:
    var z = ctx.one
    var x_mont = mont_mul(x, ctx.r2, ctx.m, ctx.n0_inv)
    var y_mont = mont_mul(y, ctx.r2, ctx.m, ctx.n0_inv)
    return PointJac(x_mont, y_mont, z)


fn to_affine(p: PointJac, ctx: P384Context) -> PointJac:
    if p.is_infinity():
        return p

    var z_inv = u384_inv_mod(p.z, ctx.m, ctx.n0_inv, ctx.one, ctx.r2)
    var z2 = mont_sqr(z_inv, ctx.m, ctx.n0_inv)
    var z3 = mont_mul(z2, z_inv, ctx.m, ctx.n0_inv)

    var x = mont_mul(p.x, z2, ctx.m, ctx.n0_inv)
    var y = mont_mul(p.y, z3, ctx.m, ctx.n0_inv)

    x = mont_mul(x, U384(1), ctx.m, ctx.n0_inv)
    y = mont_mul(y, U384(1), ctx.m, ctx.n0_inv)

    return PointJac(x, y, U384(0))


fn jac_double(p: PointJac, ctx: P384Context) -> PointJac:
    if p.is_infinity():
        return p

    var t1 = mont_sqr(p.y, ctx.m, ctx.n0_inv)
    var t2 = mont_mul(p.x, t1, ctx.m, ctx.n0_inv)
    var s = u384_add_mod(t2, t2, ctx.m)
    s = u384_add_mod(s, s, ctx.m)

    var z2 = mont_sqr(p.z, ctx.m, ctx.n0_inv)
    var x_minus = u384_sub_mod(p.x, z2, ctx.m)
    var x_plus = u384_add_mod(p.x, z2, ctx.m)
    var m_val = mont_mul(x_minus, x_plus, ctx.m, ctx.n0_inv)
    var m_val3 = u384_add_mod(m_val, m_val, ctx.m)
    m_val3 = u384_add_mod(m_val3, m_val, ctx.m)

    var m2 = mont_sqr(m_val3, ctx.m, ctx.n0_inv)
    var x3 = u384_sub_mod(u384_sub_mod(m2, s, ctx.m), s, ctx.m)

    var y2_sq = mont_sqr(t1, ctx.m, ctx.n0_inv)
    var y2_sq8 = u384_add_mod(y2_sq, y2_sq, ctx.m)
    y2_sq8 = u384_add_mod(y2_sq8, y2_sq8, ctx.m)
    y2_sq8 = u384_add_mod(y2_sq8, y2_sq8, ctx.m)

    var dy = u384_sub_mod(s, x3, ctx.m)
    var y3 = u384_sub_mod(
        mont_mul(m_val3, dy, ctx.m, ctx.n0_inv), y2_sq8, ctx.m
    )

    var yz = mont_mul(p.y, p.z, ctx.m, ctx.n0_inv)
    var z3 = u384_add_mod(yz, yz, ctx.m)

    return PointJac(x3, y3, z3)


fn jac_add(p: PointJac, q: PointJac, ctx: P384Context) -> PointJac:
    if p.is_infinity():
        return q
    if q.is_infinity():
        return p

    var z1z1 = mont_sqr(p.z, ctx.m, ctx.n0_inv)
    var z2z2 = mont_sqr(q.z, ctx.m, ctx.n0_inv)

    var u1 = mont_mul(p.x, z2z2, ctx.m, ctx.n0_inv)
    var u2 = mont_mul(q.x, z1z1, ctx.m, ctx.n0_inv)

    var z2z2z2 = mont_mul(q.z, z2z2, ctx.m, ctx.n0_inv)
    var s1 = mont_mul(p.y, z2z2z2, ctx.m, ctx.n0_inv)

    var z1z1z1 = mont_mul(p.z, z1z1, ctx.m, ctx.n0_inv)
    var s2 = mont_mul(q.y, z1z1z1, ctx.m, ctx.n0_inv)

    if u384_cmp(u1, u2) == 0:
        if u384_cmp(s1, s2) == 0:
            return jac_double(p, ctx)
        return PointJac(U384(0), U384(0), U384(0))

    var h = u384_sub_mod(u2, u1, ctx.m)
    var r = u384_sub_mod(s2, s1, ctx.m)

    var hh = mont_sqr(h, ctx.m, ctx.n0_inv)
    var hhh = mont_mul(h, hh, ctx.m, ctx.n0_inv)
    var v = mont_mul(u1, hh, ctx.m, ctx.n0_inv)

    var r2 = mont_sqr(r, ctx.m, ctx.n0_inv)
    var x3 = u384_sub_mod(r2, hhh, ctx.m)
    x3 = u384_sub_mod(x3, v, ctx.m)
    x3 = u384_sub_mod(x3, v, ctx.m)

    var dy = u384_sub_mod(v, x3, ctx.m)
    var y3 = u384_sub_mod(
        mont_mul(r, dy, ctx.m, ctx.n0_inv),
        mont_mul(s1, hhh, ctx.m, ctx.n0_inv),
        ctx.m,
    )

    var z1z2 = mont_mul(p.z, q.z, ctx.m, ctx.n0_inv)
    var z3 = mont_mul(h, z1z2, ctx.m, ctx.n0_inv)

    return PointJac(x3, y3, z3)


fn precompute_table(p: PointJac, ctx: P384Context) -> InlineArray[PointJac, 16]:
    var table = InlineArray[PointJac, 16](PointJac(U384(0), U384(0), U384(0)))
    table[1] = p
    var p2 = jac_double(p, ctx)
    table[2] = p2

    var curr = p2
    for i in range(3, 16):
        curr = jac_add(curr, p, ctx)
        table[i] = curr
    return table


fn double_scalar_mul_windowed(
    u1: U384, p1: PointJac, u2: U384, p2: PointJac, ctx: P384Context
) -> PointJac:
    var t1 = precompute_table(p1, ctx)
    var t2 = precompute_table(p2, ctx)
    var res = PointJac(U384(0), U384(0), U384(0))

    var l1 = InlineArray[UInt64, 6](0)
    l1[0] = u1.l0
    l1[1] = u1.l1
    l1[2] = u1.l2
    l1[3] = u1.l3
    l1[4] = u1.l4
    l1[5] = u1.l5

    var l2 = InlineArray[UInt64, 6](0)
    l2[0] = u2.l0
    l2[1] = u2.l1
    l2[2] = u2.l2
    l2[3] = u2.l3
    l2[4] = u2.l4
    l2[5] = u2.l5

    for i in range(96):
        var w = 95 - i
        res = jac_double(res, ctx)
        res = jac_double(res, ctx)
        res = jac_double(res, ctx)
        res = jac_double(res, ctx)

        var idx = w // 16
        var shift = (w % 16) * 4
        var val1 = (l1[idx] >> shift) & 0xF
        var val2 = (l2[idx] >> shift) & 0xF

        if val1 != 0:
            res = jac_add(res, t1[Int(val1)], ctx)
        if val2 != 0:
            res = jac_add(res, t2[Int(val2)], ctx)

    return res


fn verify_optimized(
    pub_x: U384,
    pub_y: U384,
    hash: U384,
    r: U384,
    s: U384,
    ctx: P384Context,
    scalar_ctx: ScalarContext,
) -> Bool:
    if u384_cmp(r, scalar_ctx.m) >= 0 or u384_cmp(s, scalar_ctx.m) >= 0:
        return False
    if r.is_zero() or s.is_zero():
        return False

    # s^-1 mod n
    # n - 2
    var two = U384(2)
    var n_minus_2 = u384_sub_limbs(scalar_ctx.m, two)

    # Convert s to montgomery form for scalar field
    var s_mont = mont_mul(s, scalar_ctx.r2, scalar_ctx.m, scalar_ctx.n0_inv)

    # w_mont = s^(n-2) mod n (in montgomery form)
    var w_mont = mont_pow(
        s_mont, n_minus_2, scalar_ctx.m, scalar_ctx.n0_inv, scalar_ctx.one
    )

    # Convert h and r to montgomery form
    var h_mont = mont_mul(hash, scalar_ctx.r2, scalar_ctx.m, scalar_ctx.n0_inv)
    var r_mont = mont_mul(r, scalar_ctx.r2, scalar_ctx.m, scalar_ctx.n0_inv)

    # u1 = h * w mod n
    var u1_mont = mont_mul(h_mont, w_mont, scalar_ctx.m, scalar_ctx.n0_inv)

    # u2 = r * w mod n
    var u2_mont = mont_mul(r_mont, w_mont, scalar_ctx.m, scalar_ctx.n0_inv)

    # Convert back from montgomery to normal U384 for point multiplication
    var u1 = mont_mul(u1_mont, U384(1), scalar_ctx.m, scalar_ctx.n0_inv)
    var u2 = mont_mul(u2_mont, U384(1), scalar_ctx.m, scalar_ctx.n0_inv)

    var gx = U384(
        0x3A545E3872760AB7,
        0x5502F25DBF55296C,
        0x59F741E082542A38,
        0x6E1D3B628BA79B98,
        0x8EB1C71EF320AD74,
        0xAA87CA22BE8B0537,
    )
    var gy = U384(
        0x7A431D7C90EA0E5F,
        0x0A60B1CE1D7E819D,
        0xE9DA3113B5F0B8C0,
        0xF8F41DBD289A147C,
        0x5D9E98BF9292DC29,
        0x3617DE4A96262C6F,
    )
    var G = from_affine(gx, gy, ctx)

    var Q = from_affine(pub_x, pub_y, ctx)

    var res = double_scalar_mul_windowed(u1, G, u2, Q, ctx)
    var res_aff = to_affine(res, ctx)

    var v = res_aff.x
    # v mod n
    if u384_cmp(v, scalar_ctx.m) >= 0:
        v = u384_sub_limbs(v, scalar_ctx.m)

    return u384_cmp(v, r) == 0


# ==============================================================================
# Public API
# ==============================================================================


fn verify_ecdsa_p384_hash(
    pubkey: List[UInt8], hash: List[UInt8], sig_der: List[UInt8]
) raises -> Bool:
    if len(pubkey) != 97 or pubkey[0] != 0x04:
        return False

    var pub_x_bytes = List[UInt8]()
    var pub_y_bytes = List[UInt8]()
    for i in range(1, 49):
        pub_x_bytes.append(pubkey[i])
    for i in range(49, 97):
        pub_y_bytes.append(pubkey[i])

    var pub_x = U384.from_bytes(pub_x_bytes)
    var pub_y = U384.from_bytes(pub_y_bytes)

    var hash_val = U384.from_bytes(hash)

    var reader = DerReader(sig_der)
    var seq = read_sequence_reader(reader)
    var r_bytes = read_integer_bytes(seq)
    var s_bytes = read_integer_bytes(seq)

    var r_val = U384.from_bytes(r_bytes)
    var s_val = U384.from_bytes(s_bytes)

    # Initialize Contexts (with hardcoded constants)
    var p_m = U384.p384_p()
    var p_n0_inv = UInt64(0x100000001)
    var p_r2 = U384(
        0xFFFFFFFE00000001,
        0x200000000,
        0xFFFFFFFE00000000,
        0x200000000,
        0x1,
        0x0,
    )
    var p_one = U384(0xFFFFFFFF00000001, 0xFFFFFFFF, 0x1, 0x0, 0x0, 0x0)
    var ctx = P384Context(p_m, p_n0_inv, p_r2, p_one)

    var n_m = U384.p384_n()
    var n_n0_inv = UInt64(0x6ED46089E88FDC45)
    var n_r2 = U384(
        0x2D319B2419B409A9,
        0xFF3D81E5DF1AA419,
        0xBC3E483AFCB82947,
        0xD40D49174AAB1CC5,
        0x3FB05B7A28266895,
        0xC84EE012B39BF21,
    )
    var n_one = U384(
        0x1313E695333AD68D,
        0xA7E5F24DB74F5885,
        0x389CB27E0BC8D220,
        0x0,
        0x0,
        0x0,
    )
    var scalar_ctx = ScalarContext(n_m, n_n0_inv, n_r2, n_one)

    return verify_optimized(
        pub_x, pub_y, hash_val, r_val, s_val, ctx, scalar_ctx
    )
