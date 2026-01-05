from collections import List, InlineArray
from time import perf_counter
from memory import UnsafePointer, memcpy
from bit import count_leading_zeros
from crypto.bytes import hex_to_bytes
from crypto.sha384 import sha384_bytes
from pki.bigint import BigInt, mod_mul as bi_mod_mul, mod_inv as bi_mod_inv
from pki.asn1 import DerReader, read_sequence_reader, read_integer_bytes
from testing import assert_true, assert_equal

# V2 Optimization: 
# 1. Remove "False SIMD" (scalar loops over SIMD types)
# 2. Use in-place mutation (inout) to reduce copying
# 3. Manual unrolling for 6-limb operations
# 4. Use InlineArray for fixed-size collections (stack allocation)
# 5. Remove BigInt from critical path

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
    
    fn __init__(out self, l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64, l4: UInt64, l5: UInt64):
        self.l0 = l0
        self.l1 = l1
        self.l2 = l2
        self.l3 = l3
        self.l4 = l4
        self.l5 = l5

    @always_inline
    fn is_zero(self) -> Bool:
        return (self.l0 | self.l1 | self.l2 | self.l3 | self.l4 | self.l5) == 0

    @staticmethod
    fn p384_p() -> U384:
        return U384(
            0x00000000ffffffff,
            0xffffffff00000000,
            0xfffffffffffffffe,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff
        )
    
    @staticmethod
    fn p384_n() -> U384:
        # ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
        return U384(
            0xecec196accc52973,
            0x581a0db248b0a77a,
            0xc7634d81f4372ddf,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff
        )

@always_inline
fn u384_cmp(a: U384, b: U384) -> Int:
    if a.l5 > b.l5: return 1
    if a.l5 < b.l5: return -1
    if a.l4 > b.l4: return 1
    if a.l4 < b.l4: return -1
    if a.l3 > b.l3: return 1
    if a.l3 < b.l3: return -1
    if a.l2 > b.l2: return 1
    if a.l2 < b.l2: return -1
    if a.l1 > b.l1: return 1
    if a.l1 < b.l1: return -1
    if a.l0 > b.l0: return 1
    if a.l0 < b.l0: return -1
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

# Montgomery Context
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

fn calc_n0_inv(n0: UInt64) -> UInt64:
    var inv = UInt64(1)
    for _ in range(6):
        var prod = UInt128(n0) * UInt128(inv)
        var two_minus = UInt128(2) - prod
        inv = UInt64((UInt128(inv) * two_minus) & 0xFFFFFFFFFFFFFFFF)
    return UInt64(0) - inv

fn init_scalar_context() -> ScalarContext:
    var m = U384.p384_n()
    var n0_inv = calc_n0_inv(m.l0)
    
    # R = 2^384 mod n
    # We construct R as BigInt and mul it by itself mod n
    
    var n_bytes = hex_to_bytes("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973")
    var n_bi = BigInt.from_be_bytes(n_bytes)
    
    var r_bytes = List[UInt8](capacity=49)
    r_bytes.append(1)
    for _ in range(48): r_bytes.append(0)
    var r_bi_val = BigInt.from_be_bytes(r_bytes)
    
    var rr_limbs = bi_mod_mul(r_bi_val.limbs, r_bi_val.limbs, n_bi.limbs)
    
    var r2 = U384(
        rr_limbs[0], 
        rr_limbs[1] if len(rr_limbs) > 1 else 0,
        rr_limbs[2] if len(rr_limbs) > 2 else 0,
        rr_limbs[3] if len(rr_limbs) > 3 else 0,
        rr_limbs[4] if len(rr_limbs) > 4 else 0,
        rr_limbs[5] if len(rr_limbs) > 5 else 0
    )
    
    var one_u384 = U384(1)
    var one = mont_mul(one_u384, r2, m, n0_inv)
    
    return ScalarContext(m, n0_inv, r2, one)


fn mont_mul(a: U384, b: U384, m: U384, n0_inv: UInt64) -> U384:
    # Stack allocate temporary array for product 
    # Size 12 to hold 2*N
    var t = UnsafePointer[UInt64].alloc(14) 
    for i in range(14): t[i] = 0
    
    # We unroll the inner loops for performance, avoiding SIMD overhead for short loops
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
    t[0] = UInt64(val) # Should be 0 mod 2^64
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
    var overflow = t[12] # Check spill
    t.free()

    if overflow > 0 or u384_cmp(res, m) >= 0:
        return u384_sub_limbs(res, m)
    return res

fn mont_sqr(a: U384, m: U384, n0_inv: UInt64) -> U384:
    return mont_mul(a, a, m, n0_inv)

# Point Struct
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
    # var s2 = u384_add_mod(s, s, ctx.m) # Unused
    var x3 = u384_sub_mod(u384_sub_mod(m2, s, ctx.m), s, ctx.m)
    
    var y2_sq = mont_sqr(t1, ctx.m, ctx.n0_inv)
    var y2_sq8 = u384_add_mod(y2_sq, y2_sq, ctx.m)
    y2_sq8 = u384_add_mod(y2_sq8, y2_sq8, ctx.m)
    y2_sq8 = u384_add_mod(y2_sq8, y2_sq8, ctx.m)
    
    var dy = u384_sub_mod(s, x3, ctx.m)
    var y3 = u384_sub_mod(mont_mul(m_val3, dy, ctx.m, ctx.n0_inv), y2_sq8, ctx.m)
    
    var yz = mont_mul(p.y, p.z, ctx.m, ctx.n0_inv)
    var z3 = u384_add_mod(yz, yz, ctx.m)
    
    return PointJac(x3, y3, z3)

fn jac_add(p: PointJac, q: PointJac, ctx: P384Context) -> PointJac:
    if p.is_infinity(): return q
    if q.is_infinity(): return p
    
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
    var y3 = u384_sub_mod(mont_mul(r, dy, ctx.m, ctx.n0_inv), mont_mul(s1, hhh, ctx.m, ctx.n0_inv), ctx.m)
    
    var z1z2 = mont_mul(p.z, q.z, ctx.m, ctx.n0_inv)
    var z3 = mont_mul(h, z1z2, ctx.m, ctx.n0_inv)
    
    return PointJac(x3, y3, z3)

fn p384_n0_inv() -> UInt64:
    var mod0 = UInt64(0x00000000ffffffff)
    var inv = UInt64(1)
    for _ in range(6):
        var prod = UInt128(mod0) * UInt128(inv)
        var two_minus = UInt128(2) - prod
        inv = UInt64((UInt128(inv) * two_minus) & 0xFFFFFFFFFFFFFFFF)
    return UInt64(0) - inv

fn u384_from_int(val: UInt64) -> U384:
    return U384(val)

fn init_p384_context() -> P384Context:
    var m = U384.p384_p()
    var n0_inv = p384_n0_inv()
    
    # R = 2^384 mod P
    var r_u384 = U384(
        0xffffffff00000001,
        0x00000000ffffffff,
        1,
        0, 0, 0
    )
    
    var r_limbs = List[UInt64](r_u384.l0, r_u384.l1, r_u384.l2, r_u384.l3, r_u384.l4, r_u384.l5)
    var p_bytes = hex_to_bytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff")
    var p_bi = BigInt.from_be_bytes(p_bytes)
    
    var rr_limbs = bi_mod_mul(r_limbs, r_limbs, p_bi.limbs)
    var r2 = U384(
        rr_limbs[0], 
        rr_limbs[1] if len(rr_limbs) > 1 else 0,
        rr_limbs[2] if len(rr_limbs) > 2 else 0,
        rr_limbs[3] if len(rr_limbs) > 3 else 0,
        rr_limbs[4] if len(rr_limbs) > 4 else 0,
        rr_limbs[5] if len(rr_limbs) > 5 else 0
    )
    
    var one = mont_mul(u384_from_int(1), r2, m, n0_inv)
    return P384Context(m, n0_inv, r2, one)

fn mont_pow(base: U384, exp: U384, m: U384, n0_inv: UInt64, one_mont: U384) -> U384:
    var res = one_mont
    var b = base
    
    var limbs = List[UInt64](exp.l0, exp.l1, exp.l2, exp.l3, exp.l4, exp.l5)
    
    for i in range(384):
        var limb_idx = i // 64
        var bit_idx = i % 64
        var bit = (limbs[limb_idx] >> bit_idx) & 1
        
        if bit == 1:
            res = mont_mul(res, b, m, n0_inv)
        b = mont_sqr(b, m, n0_inv)
        
    return res

fn u384_inv_mod(a: U384, m: U384, n0_inv: UInt64, one_mont: U384, r2: U384) -> U384:
    var two = U384(2)
    var exp = u384_sub_limbs(m, two)
    return mont_pow(a, exp, m, n0_inv, one_mont)

fn from_affine(x: U384, y: U384, ctx: P384Context) -> PointJac:
    var z = ctx.one
    var x_mont = mont_mul(x, ctx.r2, ctx.m, ctx.n0_inv)
    var y_mont = mont_mul(y, ctx.r2, ctx.m, ctx.n0_inv)
    return PointJac(x_mont, y_mont, z)

fn to_affine(p: PointJac, ctx: P384Context) -> PointJac:
    if p.is_infinity(): return p
    
    var z_inv = u384_inv_mod(p.z, ctx.m, ctx.n0_inv, ctx.one, ctx.r2)
    var z2 = mont_sqr(z_inv, ctx.m, ctx.n0_inv)
    var z3 = mont_mul(z2, z_inv, ctx.m, ctx.n0_inv)
    
    var x = mont_mul(p.x, z2, ctx.m, ctx.n0_inv)
    var y = mont_mul(p.y, z3, ctx.m, ctx.n0_inv)
    
    x = mont_mul(x, u384_from_int(1), ctx.m, ctx.n0_inv)
    y = mont_mul(y, u384_from_int(1), ctx.m, ctx.n0_inv)
    
    return PointJac(x, y, u384_from_int(0))

fn limbs_to_u384(limbs: List[UInt64]) -> U384:
    var l0 = limbs[0] if len(limbs) > 0 else 0
    var l1 = limbs[1] if len(limbs) > 1 else 0
    var l2 = limbs[2] if len(limbs) > 2 else 0
    var l3 = limbs[3] if len(limbs) > 3 else 0
    var l4 = limbs[4] if len(limbs) > 4 else 0
    var l5 = limbs[5] if len(limbs) > 5 else 0
    return U384(l0, l1, l2, l3, l4, l5)

fn get_msg() -> List[UInt8]:
    return hex_to_bytes("48656c6c6f204d6f6a6f2042656e63686d61726b")

fn get_p384_pub() -> List[UInt8]:
    return hex_to_bytes("04280d5497dec9fbda14637931d3a5ba60edca91ff2e9e5e9f5278acf10d371d5b2bd9e4ddc860c4c068cca7d5ca8db789129ca87576f9e0f9d172aa6061ab56ba36719c7a402c84d425da94646c105f1178326e9c323e79c87a7149bd990c4f6d")

fn get_p384_sig() -> List[UInt8]:
    return hex_to_bytes("3065023100d5132ebda8a826ce08208f819d7afd25aba53d94e316f86253ed0f547be7070368d089211e6e75c94ae9acb69847183d0230562e2b43b16cf7cf312b2e74d6b751c4144ca91579d1452cc9ea5ebdcd84f945445d9b338b232671fcd5003e74258058")

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

fn double_scalar_mul_windowed(u1: U384, p1: PointJac, u2: U384, p2: PointJac, ctx: P384Context) -> PointJac:
    var t1 = precompute_table(p1, ctx)
    var t2 = precompute_table(p2, ctx)
    var res = PointJac(U384(0), U384(0), U384(0))
    
    var l1 = InlineArray[UInt64, 6](0)
    l1[0] = u1.l0; l1[1] = u1.l1; l1[2] = u1.l2; l1[3] = u1.l3; l1[4] = u1.l4; l1[5] = u1.l5

    var l2 = InlineArray[UInt64, 6](0)
    l2[0] = u2.l0; l2[1] = u2.l1; l2[2] = u2.l2; l2[3] = u2.l3; l2[4] = u2.l4; l2[5] = u2.l5
    
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
    pub_x: U384, pub_y: U384, 
    hash: U384, r: U384, s: U384, 
    ctx: P384Context,
    scalar_ctx: ScalarContext
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
    var w_mont = mont_pow(s_mont, n_minus_2, scalar_ctx.m, scalar_ctx.n0_inv, scalar_ctx.one)
    
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
    
    var gx = U384(0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38, 0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74, 0xaa87ca22be8b0537)
    var gy = U384(0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c, 0x5d9e98bf9292dc29, 0x3617de4a96262c6f)
    var G = from_affine(gx, gy, ctx)
    
    var Q = from_affine(pub_x, pub_y, ctx)
    
    var res = double_scalar_mul_windowed(u1, G, u2, Q, ctx)
    var res_aff = to_affine(res, ctx)
    
    var v = res_aff.x
    # v mod n
    if u384_cmp(v, scalar_ctx.m) >= 0:
        v = u384_sub_limbs(v, scalar_ctx.m)
        
    return u384_cmp(v, r) == 0

fn test_correctness() raises:
    print("Initializing P-384 context...")
    var ctx = init_p384_context()
    var scalar_ctx = init_scalar_context()
    print("Context initialized.")
    
    var pub_bytes = get_p384_pub()
    var pub_x_bytes = List[UInt8]()
    var pub_y_bytes = List[UInt8]()
    for i in range(1, 49): pub_x_bytes.append(pub_bytes[i])
    for i in range(49, 97): pub_y_bytes.append(pub_bytes[i])
    
    var pub_x_bi = BigInt.from_be_bytes(pub_x_bytes)
    var pub_y_bi = BigInt.from_be_bytes(pub_y_bytes)
    var pub_x = limbs_to_u384(pub_x_bi.limbs)
    var pub_y = limbs_to_u384(pub_y_bi.limbs)
    
    var msg = get_msg()
    var digest = sha384_bytes(msg)
    var h_bi = BigInt.from_be_bytes(digest)
    var h_val = limbs_to_u384(h_bi.limbs)
    
    var reader = DerReader(get_p384_sig())
    var seq = read_sequence_reader(reader)
    var r_bytes = read_integer_bytes(seq)
    var s_bytes = read_integer_bytes(seq)
    var r_bi = BigInt.from_be_bytes(r_bytes)
    var s_bi = BigInt.from_be_bytes(s_bytes)
    var r_val = limbs_to_u384(r_bi.limbs)
    var s_val = limbs_to_u384(s_bi.limbs)
    
    print("Checking correctness...")
    var ok = verify_optimized(pub_x, pub_y, h_val, r_val, s_val, ctx, scalar_ctx)
    assert_true(ok)
    print("Correctness passed.")

    # Minimal Bench
    print("Benchmarking V2...")
    var start = perf_counter()
    var iters = 100
    for _ in range(iters):
        _ = verify_optimized(pub_x, pub_y, h_val, r_val, s_val, ctx, scalar_ctx)
    var end = perf_counter()
    var dur = end - start
    print("ECDSA P-384 Verify (Optimized V2):", iters / dur, "ops/sec")

fn main() raises:
    test_correctness()