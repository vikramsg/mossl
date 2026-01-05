"""Pure Mojo X25519 implementation (RFC 7748)."""
from collections import List


fn mask() -> UInt64:
    return (UInt64(1) << 51) - UInt64(1)


fn base() -> UInt64:
    return UInt64(1) << 51


fn p0() -> UInt64:
    return mask() - UInt64(18)


fn p1() -> UInt64:
    return mask()


fn p2() -> UInt64:
    return mask()


fn p3() -> UInt64:
    return mask()


fn p4() -> UInt64:
    return mask()


fn fe_zero() -> List[UInt64]:
    var out: List[UInt64] = [0, 0, 0, 0, 0]
    return out^


fn fe_one() -> List[UInt64]:
    var out: List[UInt64] = [UInt64(1), 0, 0, 0, 0]
    return out^


fn fe_carry(f_in: List[UInt64]) -> List[UInt64]:
    var f = f_in.copy()
    var m = mask()
    var c = f[0] >> 51
    f[1] += c
    f[0] &= m
    c = f[1] >> 51
    f[2] += c
    f[1] &= m
    c = f[2] >> 51
    f[3] += c
    f[2] &= m
    c = f[3] >> 51
    f[4] += c
    f[3] &= m
    c = f[4] >> 51
    f[0] += c * UInt64(19)
    f[4] &= m
    c = f[0] >> 51
    f[1] += c
    f[0] &= m
    return f^


fn fe_add(a: List[UInt64], b: List[UInt64]) -> List[UInt64]:
    var out = List[UInt64]()
    out.append(a[0] + b[0])
    out.append(a[1] + b[1])
    out.append(a[2] + b[2])
    out.append(a[3] + b[3])
    out.append(a[4] + b[4])
    return fe_carry(out)


fn fe_sub(a: List[UInt64], b: List[UInt64]) -> List[UInt64]:
    var out = List[UInt64]()
    var m = mask()
    out.append(a[0] + (m * UInt64(2) - UInt64(36)) - b[0])
    out.append(a[1] + (m * UInt64(2)) - b[1])
    out.append(a[2] + (m * UInt64(2)) - b[2])
    out.append(a[3] + (m * UInt64(2)) - b[3])
    out.append(a[4] + (m * UInt64(2)) - b[4])
    return fe_carry(out)


fn fe_mul(a: List[UInt64], b: List[UInt64]) -> List[UInt64]:
    var a0 = a[0]
    var a1 = a[1]
    var a2 = a[2]
    var a3 = a[3]
    var a4 = a[4]
    var b0 = b[0]
    var b1 = b[1]
    var b2 = b[2]
    var b3 = b[3]
    var b4 = b[4]
    var m = mask()

    var a1_19 = UInt128(a1) * UInt128(19)
    var a2_19 = UInt128(a2) * UInt128(19)
    var a3_19 = UInt128(a3) * UInt128(19)
    var a4_19 = UInt128(a4) * UInt128(19)

    var c0 = (
        UInt128(a0) * UInt128(b0)
        + a1_19 * UInt128(b4)
        + a2_19 * UInt128(b3)
        + a3_19 * UInt128(b2)
        + a4_19 * UInt128(b1)
    )
    var c1 = (
        UInt128(a0) * UInt128(b1)
        + UInt128(a1) * UInt128(b0)
        + a2_19 * UInt128(b4)
        + a3_19 * UInt128(b3)
        + a4_19 * UInt128(b2)
    )
    var c2 = (
        UInt128(a0) * UInt128(b2)
        + UInt128(a1) * UInt128(b1)
        + UInt128(a2) * UInt128(b0)
        + a3_19 * UInt128(b4)
        + a4_19 * UInt128(b3)
    )
    var c3 = (
        UInt128(a0) * UInt128(b3)
        + UInt128(a1) * UInt128(b2)
        + UInt128(a2) * UInt128(b1)
        + UInt128(a3) * UInt128(b0)
        + a4_19 * UInt128(b4)
    )
    var c4 = (
        UInt128(a0) * UInt128(b4)
        + UInt128(a1) * UInt128(b3)
        + UInt128(a2) * UInt128(b2)
        + UInt128(a3) * UInt128(b1)
        + UInt128(a4) * UInt128(b0)
    )

    var carry = c0 >> 51
    c1 += carry
    c0 &= UInt128(m)
    carry = c1 >> 51
    c2 += carry
    c1 &= UInt128(m)
    carry = c2 >> 51
    c3 += carry
    c2 &= UInt128(m)
    carry = c3 >> 51
    c4 += carry
    c3 &= UInt128(m)
    carry = c4 >> 51
    c0 += carry * UInt128(19)
    c4 &= UInt128(m)
    carry = c0 >> 51
    c1 += carry
    c0 &= UInt128(m)

    var out = List[UInt64]()
    out.append(UInt64(c0))
    out.append(UInt64(c1))
    out.append(UInt64(c2))
    out.append(UInt64(c3))
    out.append(UInt64(c4))
    return out^


fn fe_sq(a: List[UInt64]) -> List[UInt64]:
    return fe_mul(a, a)


fn fe_mul_small(a: List[UInt64], c: UInt64) -> List[UInt64]:
    var m = mask()
    var t0 = UInt128(a[0]) * UInt128(c)
    var t1 = UInt128(a[1]) * UInt128(c)
    var t2 = UInt128(a[2]) * UInt128(c)
    var t3 = UInt128(a[3]) * UInt128(c)
    var t4 = UInt128(a[4]) * UInt128(c)

    var carry = t0 >> 51
    t1 += carry
    t0 &= UInt128(m)
    carry = t1 >> 51
    t2 += carry
    t1 &= UInt128(m)
    carry = t2 >> 51
    t3 += carry
    t2 &= UInt128(m)
    carry = t3 >> 51
    t4 += carry
    t3 &= UInt128(m)
    carry = t4 >> 51
    t0 += carry * UInt128(19)
    t4 &= UInt128(m)
    carry = t0 >> 51
    t1 += carry
    t0 &= UInt128(m)

    var out = List[UInt64]()
    out.append(UInt64(t0))
    out.append(UInt64(t1))
    out.append(UInt64(t2))
    out.append(UInt64(t3))
    out.append(UInt64(t4))
    return out^


fn fe_sq_pow(a: List[UInt64], n: Int) -> List[UInt64]:
    var out = a.copy()
    var i = 0
    while i < n:
        out = fe_sq(out)
        i += 1
    return out^


fn fe_invert(z: List[UInt64]) -> List[UInt64]:
    var t0 = fe_sq(z)
    var t1 = fe_sq(t0)
    t1 = fe_sq(t1)
    t1 = fe_mul(t1, z)
    t0 = fe_mul(t0, t1)
    var t2 = fe_sq(t0)
    t1 = fe_mul(t1, t2)
    t2 = fe_sq_pow(t1, 5)
    t1 = fe_mul(t2, t1)
    t2 = fe_sq_pow(t1, 10)
    t2 = fe_mul(t2, t1)
    var t3 = fe_sq_pow(t2, 20)
    t2 = fe_mul(t3, t2)
    t2 = fe_sq_pow(t2, 10)
    t1 = fe_mul(t2, t1)
    t2 = fe_sq_pow(t1, 50)
    t2 = fe_mul(t2, t1)
    t3 = fe_sq_pow(t2, 100)
    t2 = fe_mul(t3, t2)
    t2 = fe_sq_pow(t2, 50)
    t1 = fe_mul(t2, t1)
    t1 = fe_sq_pow(t1, 5)
    return fe_mul(t1, t0)


fn load64_le(bytes: List[UInt8], offset: Int) -> UInt64:
    var out = UInt64(0)
    var i = 0
    while i < 8:
        out |= UInt64(bytes[offset + i]) << (i * 8)
        i += 1
    return out


fn fe_from_bytes(s: List[UInt8]) -> List[UInt64]:
    var m = mask()
    var t0 = load64_le(s, 0)
    var t1 = load64_le(s, 8)
    var t2 = load64_le(s, 16)
    var t3 = load64_le(s, 24)
    var f0 = t0 & m
    var f1 = ((t0 >> 51) | (t1 << 13)) & m
    var f2 = ((t1 >> 38) | (t2 << 26)) & m
    var f3 = ((t2 >> 25) | (t3 << 39)) & m
    var f4 = (t3 >> 12) & m
    var out = List[UInt64]()
    out.append(f0)
    out.append(f1)
    out.append(f2)
    out.append(f3)
    out.append(f4)
    return out^


fn fe_ge_p(f: List[UInt64]) -> Bool:
    var p4v = p4()
    var p3v = p3()
    var p2v = p2()
    var p1v = p1()
    var p0v = p0()
    if f[4] > p4v:
        return True
    if f[4] < p4v:
        return False
    if f[3] > p3v:
        return True
    if f[3] < p3v:
        return False
    if f[2] > p2v:
        return True
    if f[2] < p2v:
        return False
    if f[1] > p1v:
        return True
    if f[1] < p1v:
        return False
    return f[0] >= p0v


fn fe_sub_p(f: List[UInt64]) -> List[UInt64]:
    var out = List[UInt64]()
    var borrow = Int(0)
    var basev = Int(base())
    var p = List[UInt64]()
    p.append(p0())
    p.append(p1())
    p.append(p2())
    p.append(p3())
    p.append(p4())
    var i = 0
    while i < 5:
        var tmp = Int(f[i]) - Int(p[i]) - borrow
        if tmp < 0:
            tmp += basev
            borrow = 1
        else:
            borrow = 0
        out.append(UInt64(tmp))
        i += 1
    return out^


fn append_u64_le(mut buf: List[UInt8], value: UInt64):
    var i = 0
    while i < 8:
        buf.append(UInt8((value >> (i * 8)) & UInt64(0xFF)))
        i += 1


fn fe_to_bytes(f_in: List[UInt64]) -> List[UInt8]:
    var f = fe_carry(f_in)
    if fe_ge_p(f):
        f = fe_sub_p(f)

    var t0 = UInt64(UInt128(f[0]) | (UInt128(f[1]) << 51))
    var t1 = UInt64((UInt128(f[1]) >> 13) | (UInt128(f[2]) << 38))
    var t2 = UInt64((UInt128(f[2]) >> 26) | (UInt128(f[3]) << 25))
    var t3 = UInt64((UInt128(f[3]) >> 39) | (UInt128(f[4]) << 12))

    var out = List[UInt8]()
    append_u64_le(out, t0)
    append_u64_le(out, t1)
    append_u64_le(out, t2)
    append_u64_le(out, t3)
    return out^


fn clamp_scalar(k_in: List[UInt8]) -> List[UInt8]:
    var k = List[UInt8]()
    for b in k_in:
        k.append(b)
    k[0] &= UInt8(248)
    k[31] &= UInt8(127)
    k[31] |= UInt8(64)
    return k^


from time import perf_counter

struct Timer:
    var start: Float64
    var name: String

    fn __init__(out self, name: String):
        self.name = name
        self.start = perf_counter()
        print("    [X25519-DEBUG] Starting " + self.name)

    fn stop(self):
        var end = perf_counter()
        print("    [X25519-TIMER] " + self.name + ": " + String(end - self.start) + "s")

fn x25519(scalar: List[UInt8], u: List[UInt8]) -> List[UInt8]:
    var t_total = Timer("x25519")
    var k = clamp_scalar(scalar)
    var x1 = fe_from_bytes(u)
    var x2 = fe_one()
    var z2 = fe_zero()
    var x3 = x1.copy()
    var z3 = fe_one()
    var swap = 0

    var t = 254
    while t >= 0:
        var byte_index = t >> 3
        var bit_index = t & 7
        var kt = (Int(k[byte_index]) >> bit_index) & 1
        swap ^= kt
        if swap == 1:
            var tmp = x2.copy()
            x2 = x3.copy()
            x3 = tmp.copy()
            tmp = z2.copy()
            z2 = z3.copy()
            z3 = tmp.copy()
        swap = kt

        var a = fe_add(x2, z2)
        var aa = fe_sq(a)
        var b = fe_sub(x2, z2)
        var bb = fe_sq(b)
        var e = fe_sub(aa, bb)
        var c = fe_add(x3, z3)
        var d = fe_sub(x3, z3)
        var da = fe_mul(d, a)
        var cb = fe_mul(c, b)
        var x3_new = fe_sq(fe_add(da, cb))
        var z3_new = fe_mul(x1, fe_sq(fe_sub(da, cb)))
        var x2_new = fe_mul(aa, bb)
        var z2_new = fe_mul(e, fe_add(aa, fe_mul_small(e, UInt64(121665))))
        x3 = x3_new.copy()
        z3 = z3_new.copy()
        x2 = x2_new.copy()
        z2 = z2_new.copy()
        t -= 1

    if swap == 1:
        x2 = x3.copy()
        z2 = z3.copy()

    var z2_inv = fe_invert(z2)
    var out = fe_mul(x2, z2_inv)
    var res = fe_to_bytes(out)
    t_total.stop()
    return res
