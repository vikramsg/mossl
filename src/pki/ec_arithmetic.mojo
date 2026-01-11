from collections import InlineArray
from sys import bitwidthof

from memory import UnsafePointer


struct UIntLimbs[N: Int](Copyable, ImplicitlyCopyable, Movable):
    var limbs: InlineArray[UInt64, N]

    fn __init__(out self):
        self.limbs = InlineArray[UInt64, N](0)

    fn __init__(out self, val: UInt64):
        self.limbs = InlineArray[UInt64, N](0)
        self.limbs[0] = val

    fn __init__(out self, src: InlineArray[UInt64, N]):
        self.limbs = src

    fn __copyinit__(out self, other: Self):
        self.limbs = other.limbs

    fn __moveinit__(out self, deinit other: Self):
        self.limbs = other.limbs

    @always_inline
    fn is_zero(self) -> Bool:
        var res = UInt64(0)
        for i in range(N):
            res |= self.limbs[i]
        return res == 0

    @staticmethod
    fn from_bytes(bytes: List[UInt8]) -> UIntLimbs[N]:
        # Big Endian
        var res = UIntLimbs[N]()
        var total_bytes = N * 8
        var b_len = len(bytes)

        var padded = List[UInt8]()
        # Pad with leading zeros if too short
        if b_len < total_bytes:
            for _ in range(total_bytes - b_len):
                padded.append(0)
            for i in range(b_len):
                padded.append(bytes[i])
        else:
            # Take last total_bytes if too long
            var start = b_len - total_bytes
            for i in range(total_bytes):
                padded.append(bytes[start + i])

        for i in range(N):
            var val = UInt64(0)
            for j in range(8):
                val = (val << 8) | UInt64(padded[(N - 1 - i) * 8 + j])
            res.limbs[i] = val

        return res


fn cmp[N: Int](a: UIntLimbs[N], b: UIntLimbs[N]) -> Int:
    """Compares two UIntLimbs (Public API)."""
    return _cmp(a, b)


fn sub_limbs[N: Int](a: UIntLimbs[N], b: UIntLimbs[N]) -> UIntLimbs[N]:
    """Subtracts two UIntLimbs (Public API)."""
    return _sub_limbs(a, b)


fn mont_mul[
    N: Int
](
    a: UIntLimbs[N], b: UIntLimbs[N], m: UIntLimbs[N], n0_inv: UInt64
) -> UIntLimbs[N]:
    """Performs Montgomery multiplication (Public API)."""
    return _mont_mul(a, b, m, n0_inv)


@always_inline
fn _cmp[N: Int](a: UIntLimbs[N], b: UIntLimbs[N]) -> Int:
    for i in range(N):
        var idx = N - 1 - i
        if a.limbs[idx] > b.limbs[idx]:
            return 1
        if a.limbs[idx] < b.limbs[idx]:
            return -1
    return 0


@always_inline
fn _sub_limbs[N: Int](a: UIntLimbs[N], b: UIntLimbs[N]) -> UIntLimbs[N]:
    var res = UIntLimbs[N]()
    var borrow = Int128(0)

    for i in range(N):
        var d = Int128(a.limbs[i]) - Int128(b.limbs[i]) - borrow
        res.limbs[i] = UInt64(d & 0xFFFFFFFFFFFFFFFF)
        borrow = 1 if d < 0 else 0

    return res


@always_inline
fn _add_mod[
    N: Int
](a: UIntLimbs[N], b: UIntLimbs[N], m: UIntLimbs[N]) -> UIntLimbs[N]:
    var res = UIntLimbs[N]()
    var carry = UInt64(0)

    for i in range(N):
        var s = UInt128(a.limbs[i]) + UInt128(b.limbs[i]) + UInt128(carry)
        res.limbs[i] = UInt64(s)
        carry = UInt64(s >> 64)

    if carry > 0 or _cmp(res, m) >= 0:
        return _sub_limbs(res, m)
    return res


@always_inline
fn _sub_mod[
    N: Int
](a: UIntLimbs[N], b: UIntLimbs[N], m: UIntLimbs[N]) -> UIntLimbs[N]:
    if _cmp(a, b) >= 0:
        return _sub_limbs(a, b)
    var diff = _sub_limbs(a, b)
    # Add modulus
    var res = UIntLimbs[N]()
    var carry = UInt64(0)
    for i in range(N):
        var s = UInt128(diff.limbs[i]) + UInt128(m.limbs[i]) + UInt128(carry)
        res.limbs[i] = UInt64(s)
        carry = UInt64(s >> 64)
    return res


fn _mont_mul[
    N: Int
](
    a: UIntLimbs[N], b: UIntLimbs[N], m: UIntLimbs[N], n0_inv: UInt64
) -> UIntLimbs[N]:
    # CIOS Montgomery Multiplication
    var t_len = 2 * N + 2
    var t = UnsafePointer[UInt64].alloc(t_len)
    for i in range(t_len):
        t[i] = 0

    # Outer loop A
    for i in range(N):
        var carry = UInt128(0)
        var u_i = UInt128(a.limbs[i])

        # T[i+j] += A[i] * B[j] + C
        for j in range(N):
            var val = UInt128(t[i + j]) + u_i * UInt128(b.limbs[j]) + carry
            t[i + j] = UInt64(val)
            carry = val >> 64

        t[i + N] = UInt64(carry)

    # Reduction
    for i in range(N):
        # m = (T[i] * n0') mod 2^64
        var u = UInt64((UInt128(t[i]) * UInt128(n0_inv)) & 0xFFFFFFFFFFFFFFFF)

        # T += m * N shifted by i blocks (actually we just add to T[i...])
        var carry = UInt128(0)
        var u_128 = UInt128(u)

        for j in range(N):
            var val = UInt128(t[i + j]) + u_128 * UInt128(m.limbs[j]) + carry
            t[i + j] = UInt64(val)
            carry = val >> 64

        # Propagate carry
        var k = i + N
        while carry > 0:
            var val = UInt128(t[k]) + carry
            t[k] = UInt64(val)
            carry = val >> 64
            k += 1

    # Result is in t[N ... 2N-1]
    var res = UIntLimbs[N]()
    for i in range(N):
        res.limbs[i] = t[N + i]

    var overflow = t[2 * N]
    t.free()

    if overflow > 0 or _cmp(res, m) >= 0:
        return _sub_limbs(res, m)

    return res


fn _mont_sqr[
    N: Int
](a: UIntLimbs[N], m: UIntLimbs[N], n0_inv: UInt64) -> UIntLimbs[N]:
    return _mont_mul(a, a, m, n0_inv)


fn _mont_pow[
    N: Int
](
    base: UIntLimbs[N],
    exp: UIntLimbs[N],
    m: UIntLimbs[N],
    n0_inv: UInt64,
    one_mont: UIntLimbs[N],
) -> UIntLimbs[N]:
    var res = one_mont
    var b = base

    # Scan bits of exp
    for i in range(N * 64):
        var limb_idx = i // 64
        var bit_idx = i % 64
        var bit = (exp.limbs[limb_idx] >> bit_idx) & 1

        if bit == 1:
            res = _mont_mul(res, b, m, n0_inv)
        b = _mont_sqr(b, m, n0_inv)

    return res


@fieldwise_init
struct FieldContext[N: Int](Copyable, ImplicitlyCopyable, Movable):
    var m: UIntLimbs[N]
    var n0_inv: UInt64
    var r2: UIntLimbs[N]
    var one: UIntLimbs[N]


fn _inv_mod[N: Int](a: UIntLimbs[N], ctx: FieldContext[N]) -> UIntLimbs[N]:
    var two = UIntLimbs[N](2)
    var exp = _sub_limbs(ctx.m, two)
    return _mont_pow(a, exp, ctx.m, ctx.n0_inv, ctx.one)


@fieldwise_init
struct PointJac[N: Int](Copyable, ImplicitlyCopyable, Movable):
    var x: UIntLimbs[N]
    var y: UIntLimbs[N]
    var z: UIntLimbs[N]

    fn is_infinity(self) -> Bool:
        return self.z.is_zero()


fn _from_affine[
    N: Int
](x: UIntLimbs[N], y: UIntLimbs[N], ctx: FieldContext[N]) -> PointJac[N]:
    var z = ctx.one
    var x_mont = _mont_mul(x, ctx.r2, ctx.m, ctx.n0_inv)
    var y_mont = _mont_mul(y, ctx.r2, ctx.m, ctx.n0_inv)
    return PointJac(x_mont, y_mont, z)


fn _to_affine[N: Int](p: PointJac[N], ctx: FieldContext[N]) -> PointJac[N]:
    if p.is_infinity():
        return p

    var z_inv = _inv_mod(p.z, ctx)
    var z2 = _mont_sqr(z_inv, ctx.m, ctx.n0_inv)
    var z3 = _mont_mul(z2, z_inv, ctx.m, ctx.n0_inv)

    var x = _mont_mul(p.x, z2, ctx.m, ctx.n0_inv)
    var y = _mont_mul(p.y, z3, ctx.m, ctx.n0_inv)

    x = _mont_mul(x, UIntLimbs[N](1), ctx.m, ctx.n0_inv)
    y = _mont_mul(y, UIntLimbs[N](1), ctx.m, ctx.n0_inv)

    return PointJac(x, y, UIntLimbs[N](0))


fn _jac_double[N: Int](p: PointJac[N], ctx: FieldContext[N]) -> PointJac[N]:
    if p.is_infinity():
        return p

    var t1 = _mont_sqr(p.y, ctx.m, ctx.n0_inv)
    var t2 = _mont_mul(p.x, t1, ctx.m, ctx.n0_inv)
    var s = _add_mod(t2, t2, ctx.m)
    s = _add_mod(s, s, ctx.m)

    var z2 = _mont_sqr(p.z, ctx.m, ctx.n0_inv)
    var x_minus = _sub_mod(p.x, z2, ctx.m)
    var x_plus = _add_mod(p.x, z2, ctx.m)
    var m_val = _mont_mul(x_minus, x_plus, ctx.m, ctx.n0_inv)
    var m_val3 = _add_mod(m_val, m_val, ctx.m)
    m_val3 = _add_mod(m_val3, m_val, ctx.m)

    var m2 = _mont_sqr(m_val3, ctx.m, ctx.n0_inv)
    var x3 = _sub_mod(_sub_mod(m2, s, ctx.m), s, ctx.m)

    var y2_sq = _mont_sqr(t1, ctx.m, ctx.n0_inv)
    var y2_sq8 = _add_mod(y2_sq, y2_sq, ctx.m)
    y2_sq8 = _add_mod(y2_sq8, y2_sq8, ctx.m)
    y2_sq8 = _add_mod(y2_sq8, y2_sq8, ctx.m)

    var dy = _sub_mod(s, x3, ctx.m)
    var y3 = _sub_mod(_mont_mul(m_val3, dy, ctx.m, ctx.n0_inv), y2_sq8, ctx.m)

    var yz = _mont_mul(p.y, p.z, ctx.m, ctx.n0_inv)
    var z3 = _add_mod(yz, yz, ctx.m)

    return PointJac(x3, y3, z3)


fn _jac_add[
    N: Int
](p: PointJac[N], q: PointJac[N], ctx: FieldContext[N]) -> PointJac[N]:
    if p.is_infinity():
        return q
    if q.is_infinity():
        return p

    var z1z1 = _mont_sqr(p.z, ctx.m, ctx.n0_inv)
    var z2z2 = _mont_sqr(q.z, ctx.m, ctx.n0_inv)

    var u1 = _mont_mul(p.x, z2z2, ctx.m, ctx.n0_inv)
    var u2 = _mont_mul(q.x, z1z1, ctx.m, ctx.n0_inv)

    var z2z2z2 = _mont_mul(q.z, z2z2, ctx.m, ctx.n0_inv)
    var s1 = _mont_mul(p.y, z2z2z2, ctx.m, ctx.n0_inv)

    var z1z1z1 = _mont_mul(p.z, z1z1, ctx.m, ctx.n0_inv)
    var s2 = _mont_mul(q.y, z1z1z1, ctx.m, ctx.n0_inv)

    if _cmp(u1, u2) == 0:
        if _cmp(s1, s2) == 0:
            return _jac_double(p, ctx)
        return PointJac(UIntLimbs[N](0), UIntLimbs[N](0), UIntLimbs[N](0))

    var h = _sub_mod(u2, u1, ctx.m)
    var r = _sub_mod(s2, s1, ctx.m)

    var hh = _mont_sqr(h, ctx.m, ctx.n0_inv)
    var hhh = _mont_mul(h, hh, ctx.m, ctx.n0_inv)
    var v = _mont_mul(u1, hh, ctx.m, ctx.n0_inv)

    var r2 = _mont_sqr(r, ctx.m, ctx.n0_inv)
    var x3 = _sub_mod(r2, hhh, ctx.m)
    x3 = _sub_mod(x3, v, ctx.m)
    x3 = _sub_mod(x3, v, ctx.m)

    var dy = _sub_mod(v, x3, ctx.m)
    var y3 = _sub_mod(
        _mont_mul(r, dy, ctx.m, ctx.n0_inv),
        _mont_mul(s1, hhh, ctx.m, ctx.n0_inv),
        ctx.m,
    )

    var z1z2 = _mont_mul(p.z, q.z, ctx.m, ctx.n0_inv)
    var z3 = _mont_mul(h, z1z2, ctx.m, ctx.n0_inv)

    return PointJac(x3, y3, z3)


fn _precompute_table[
    N: Int
](p: PointJac[N], ctx: FieldContext[N]) -> InlineArray[PointJac[N], 16]:
    var zero = PointJac(UIntLimbs[N](0), UIntLimbs[N](0), UIntLimbs[N](0))
    var table = InlineArray[PointJac[N], 16](zero)
    table[1] = p
    var p2 = _jac_double(p, ctx)
    table[2] = p2

    var curr = p2
    for i in range(3, 16):
        curr = _jac_add(curr, p, ctx)
        table[i] = curr
    return table


fn _double_scalar_mul_windowed[
    N: Int
](
    u1: UIntLimbs[N],
    p1: PointJac[N],
    u2: UIntLimbs[N],
    p2: PointJac[N],
    ctx: FieldContext[N],
) -> PointJac[N]:
    var t1 = _precompute_table(p1, ctx)
    var t2 = _precompute_table(p2, ctx)
    var res = PointJac(UIntLimbs[N](0), UIntLimbs[N](0), UIntLimbs[N](0))

    # Iterate from top bit down.
    # N * 64 bits.
    # Window size 4.
    var bits = N * 64
    var steps = bits // 4

    for i in range(steps):
        var w = steps - 1 - i
        res = _jac_double(res, ctx)
        res = _jac_double(res, ctx)
        res = _jac_double(res, ctx)
        res = _jac_double(res, ctx)

        var limb_idx = w // 16  # which 64-bit limb
        var shift = (w % 16) * 4

        var val1 = (u1.limbs[limb_idx] >> shift) & 0xF
        var val2 = (u2.limbs[limb_idx] >> shift) & 0xF

        if val1 != 0:
            res = _jac_add(res, t1[Int(val1)], ctx)
        if val2 != 0:
            res = _jac_add(res, t2[Int(val2)], ctx)

    return res


fn verify_generic[
    N: Int
](
    pub_x: UIntLimbs[N],
    pub_y: UIntLimbs[N],
    hash: UIntLimbs[N],
    r: UIntLimbs[N],
    s: UIntLimbs[N],
    gx: UIntLimbs[N],
    gy: UIntLimbs[N],
    ctx: FieldContext[N],
    scalar_ctx: FieldContext[N],
) -> Bool:
    if _cmp(r, scalar_ctx.m) >= 0 or _cmp(s, scalar_ctx.m) >= 0:
        return False
    if r.is_zero() or s.is_zero():
        return False

    # s^-1 mod n
    var two = UIntLimbs[N](2)
    var n_minus_2 = _sub_limbs(scalar_ctx.m, two)

    # s to mont
    var s_mont = _mont_mul(s, scalar_ctx.r2, scalar_ctx.m, scalar_ctx.n0_inv)
    var w_mont = _mont_pow(
        s_mont, n_minus_2, scalar_ctx.m, scalar_ctx.n0_inv, scalar_ctx.one
    )

    var h_mont = _mont_mul(hash, scalar_ctx.r2, scalar_ctx.m, scalar_ctx.n0_inv)
    var r_mont = _mont_mul(r, scalar_ctx.r2, scalar_ctx.m, scalar_ctx.n0_inv)

    var u1_mont = _mont_mul(h_mont, w_mont, scalar_ctx.m, scalar_ctx.n0_inv)
    var u2_mont = _mont_mul(r_mont, w_mont, scalar_ctx.m, scalar_ctx.n0_inv)

    # From mont to normal
    var u1 = _mont_mul(u1_mont, UIntLimbs[N](1), scalar_ctx.m, scalar_ctx.n0_inv)
    var u2 = _mont_mul(u2_mont, UIntLimbs[N](1), scalar_ctx.m, scalar_ctx.n0_inv)

    var G = _from_affine(gx, gy, ctx)
    var Q = _from_affine(pub_x, pub_y, ctx)

    var res = _double_scalar_mul_windowed(u1, G, u2, Q, ctx)
    var res_aff = _to_affine(res, ctx)

    var v = res_aff.x
    if _cmp(v, scalar_ctx.m) >= 0:
        v = _sub_limbs(v, scalar_ctx.m)

    return _cmp(v, r) == 0
