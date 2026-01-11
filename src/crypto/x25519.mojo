"""Pure Mojo X25519 implementation (RFC 7748).
Refactored to use InlineArray and return-based API for idiomatic Mojo.
"""

from collections import InlineArray

from memory import Span

alias FE = InlineArray[UInt64, 5]


@always_inline
fn mask() -> UInt64:
    """Returns the bitmask for 51-bit limbs."""
    return (UInt64(1) << 51) - UInt64(1)


@always_inline
fn base() -> UInt64:
    """Returns the base (2^51) for the limbs."""
    return UInt64(1) << 51


@always_inline
fn p0() -> UInt64:
    """Returns the first limb of the prime p = 2^255 - 19."""
    return mask() - UInt64(18)


@always_inline
fn p1() -> UInt64:
    """Returns the second limb of the prime p."""
    return mask()


@always_inline
fn p2() -> UInt64:
    """Returns the third limb of the prime p."""
    return mask()


@always_inline
fn p3() -> UInt64:
    """Returns the fourth limb of the prime p."""
    return mask()


@always_inline
fn p4() -> UInt64:
    """Returns the fifth limb of the prime p."""
    return mask()


fn fe_zero() -> FE:
    """Returns a field element initialized to zero."""
    return FE(0, 0, 0, 0, 0)


fn fe_one() -> FE:
    """Returns a field element initialized to one."""
    return FE(UInt64(1), 0, 0, 0, 0)


fn fe_carry(f_in: FE) -> FE:
    """Propagates carries through the field element.

    Args:
        f_in: The field element to carry.

    Returns:
        The reduced field element.
    """
    var f = f_in
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
    return f


fn fe_add(a: FE, b: FE) -> FE:
    """Adds two field elements.

    Args:
        a: First field element.
        b: Second field element.

    Returns:
        The sum a + b mod p.
    """
    var out = FE(
        a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]
    )
    return fe_carry(out)


fn fe_sub(a: FE, b: FE) -> FE:
    """Subtracts one field element from another.

    Args:
        a: Field element to subtract from.
        b: Field element to subtract.

    Returns:
        The difference a - b mod p.
    """
    var m = mask()
    var out = FE(
        a[0] + (m * UInt64(2) - UInt64(36)) - b[0],
        a[1] + (m * UInt64(2)) - b[1],
        a[2] + (m * UInt64(2)) - b[2],
        a[3] + (m * UInt64(2)) - b[3],
        a[4] + (m * UInt64(2)) - b[4],
    )
    return fe_carry(out)


fn fe_mul(a: FE, b: FE) -> FE:
    """Multiplies two field elements.

    Args:
        a: First field element.
        b: Second field element.

    Returns:
        The product a * b mod p.
    """
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

    return FE(UInt64(c0), UInt64(c1), UInt64(c2), UInt64(c3), UInt64(c4))


fn fe_sq(a: FE) -> FE:
    """Computes the square of a field element."""
    return fe_mul(a, a)


fn fe_mul_small(a: FE, c: UInt64) -> FE:
    """Multiplies a field element by a small constant.

    Args:
        a: The field element.
        c: The small constant factor.

    Returns:
        The product a * c mod p.
    """
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

    return FE(UInt64(t0), UInt64(t1), UInt64(t2), UInt64(t3), UInt64(t4))


fn fe_sq_pow(a: FE, n: Int) -> FE:
    """Computes a^(2^n) mod p.

    Args:
        a: The base field element.
        n: The power of two exponent.

    Returns:
        The result of repeated squaring.
    """
    var out = a
    for _ in range(n):
        out = fe_sq(out)
    return out


fn fe_invert(z: FE) -> FE:
    """Computes the modular inverse of a field element using Fermat's Little Theorem.

    Args:
        z: The field element to invert.

    Returns:
        The inverse z^-1 mod p.
    """
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


fn load64_le(bytes: Span[UInt8], offset: Int) -> UInt64:
    """Loads a 64-bit integer from bytes in little-endian order.

    Args:
        bytes: The source bytes.
        offset: Start position in the source bytes.

    Returns:
        The loaded 64-bit integer.
    """
    var out = UInt64(0)
    for i in range(8):
        out |= UInt64(bytes[offset + i]) << (i * 8)
    return out


fn fe_from_bytes(s: Span[UInt8]) -> FE:
    """Converts a 32-byte span to a field element.

    Args:
        s: 32-byte input span.

    Returns:
        The field element representation.
    """
    var m = mask()
    var t0 = load64_le(s, 0)
    var t1 = load64_le(s, 8)
    var t2 = load64_le(s, 16)
    var t3 = load64_le(s, 24)
    return FE(
        t0 & m,
        ((t0 >> 51) | (t1 << 13)) & m,
        ((t1 >> 38) | (t2 << 26)) & m,
        ((t2 >> 25) | (t3 << 39)) & m,
        (t3 >> 12) & m,
    )


fn fe_ge_p(f: FE) -> Bool:
    """Returns true if the field element is greater than or equal to p."""
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


fn fe_sub_p(f: FE) -> FE:
    """Subtracts the prime p from the field element.

    Args:
        f: The field element.

    Returns:
        The result f - p.
    """
    var borrow = Int(0)
    var basev = Int(base())
    var p = FE(p0(), p1(), p2(), p3(), p4())
    var out = FE(0)
    for i in range(5):
        var tmp = Int(f[i]) - Int(p[i]) - borrow
        if tmp < 0:
            tmp += basev
            borrow = 1
        else:
            borrow = 0
        out[i] = UInt64(tmp)
    return out


fn fe_to_bytes(f_in: FE) -> InlineArray[UInt8, 32]:
    """Converts a field element to 32 bytes in little-endian order.

    Args:
        f_in: The field element to convert.

    Returns:
        The 32-byte representation.
    """
    var f = fe_carry(f_in)
    if fe_ge_p(f):
        f = fe_sub_p(f)

    var t0 = UInt64(UInt128(f[0]) | (UInt128(f[1]) << 51))
    var t1 = UInt64((UInt128(f[1]) >> 13) | (UInt128(f[2]) << 38))
    var t2 = UInt64((UInt128(f[2]) >> 26) | (UInt128(f[3]) << 25))
    var t3 = UInt64((UInt128(f[3]) >> 39) | (UInt128(f[4]) << 12))

    var out = InlineArray[UInt8, 32](0)
    for i in range(8):
        out[i] = UInt8((t0 >> (i * 8)) & UInt64(0xFF))
        out[8 + i] = UInt8((t1 >> (i * 8)) & UInt64(0xFF))
        out[16 + i] = UInt8((t2 >> (i * 8)) & UInt64(0xFF))
        out[24 + i] = UInt8((t3 >> (i * 8)) & UInt64(0xFF))
    return out


fn fe_swap(mut a: FE, mut b: FE, choice: Int):
    """Constant-time swap of two field elements.

    Args:
        a: First field element.
        b: Second field element.
        choice: 1 to swap, 0 to keep.
    """
    var maskv = UInt64(0) - UInt64(choice)
    for i in range(5):
        var t = maskv & (a[i] ^ b[i])
        a[i] ^= t
        b[i] ^= t


fn x25519(
    scalar_in: Span[UInt8], u: Span[UInt8]
) raises -> InlineArray[UInt8, 32]:
    """Performs X25519 key exchange (RFC 7748).

    Args:
        scalar_in: The 32-byte private key.
        u: The 32-byte public key coordinate.

    Returns:
        The computed 32-byte shared secret.

    Raises:
        Error: If internal arithmetic error occurs.
    """
    var k = InlineArray[UInt8, 32](0)
    for i in range(32):
        k[i] = scalar_in[i]
    k[0] &= UInt8(248)
    k[31] &= UInt8(127)
    k[31] |= UInt8(64)

    var x1 = fe_from_bytes(u)
    var x2 = fe_one()
    var z2 = fe_zero()
    var x3 = x1
    var z3 = fe_one()
    var swap = 0
    var t = 254
    while t >= 0:
        var byte_index = t >> 3
        var bit_index = t & 7
        var kt = (Int(k[byte_index]) >> bit_index) & 1
        swap ^= kt
        fe_swap(x2, x3, swap)
        fe_swap(z2, z3, swap)
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
        x3 = x3_new
        z3 = z3_new
        x2 = x2_new
        z2 = z2_new
        t -= 1
    if swap == 1:
        x2 = x3
        z2 = z3
    return fe_to_bytes(fe_mul(x2, fe_invert(z2)))
