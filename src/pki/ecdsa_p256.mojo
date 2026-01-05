"""ECDSA P-256 verification (affine, minimal)."""
from collections import List

from pki.asn1 import DerReader, read_sequence_reader, read_integer_bytes

from crypto.bytes import hex_to_bytes
from crypto.sha256 import sha256_bytes

from pki.bigint256 import (
    u256_from_be,
    cmp_limbs,
    is_zero,
    add_mod,
    sub_mod,
    mod_mul,
    mod_inv,
    mod_reduce,
)


@fieldwise_init
struct ECPoint(Movable):
    var x: List[UInt64]
    var y: List[UInt64]
    var infinity: Bool

    fn clone(self) -> ECPoint:
        return ECPoint(self.x.copy(), self.y.copy(), self.infinity)


@fieldwise_init
struct JacobianPoint(Movable):
    var x: List[UInt64]
    var y: List[UInt64]
    var z: List[UInt64]
    var infinity: Bool

    fn clone(self) -> JacobianPoint:
        return JacobianPoint(
            self.x.copy(), self.y.copy(), self.z.copy(), self.infinity
        )


fn u256_from_hex(hex: String) -> List[UInt64]:
    return u256_from_be(hex_to_bytes(hex))


fn u256_const(v: UInt64) -> List[UInt64]:
    var out = List[UInt64]()
    out.append(v)
    out.append(UInt64(0))
    out.append(UInt64(0))
    out.append(UInt64(0))
    return out^


fn p256_p() -> List[UInt64]:
    return u256_from_hex(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
    )


fn p256_n() -> List[UInt64]:
    return u256_from_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    )


fn p256_gx() -> List[UInt64]:
    return u256_from_hex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    )


fn p256_gy() -> List[UInt64]:
    return u256_from_hex(
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    )


fn point_infinity() -> ECPoint:
    var zero = List[UInt64]()
    zero.append(UInt64(0))
    zero.append(UInt64(0))
    zero.append(UInt64(0))
    zero.append(UInt64(0))
    var zero_y = zero.copy()
    return ECPoint(zero^, zero_y^, True)


fn jacobian_infinity() -> JacobianPoint:
    var zero = u256_const(UInt64(0))
    var one = u256_const(UInt64(1))
    var x = zero.copy()
    return JacobianPoint(x^, one^, zero^, True)


fn jacobian_from_affine(p: ECPoint) -> JacobianPoint:
    if p.infinity:
        return jacobian_infinity()
    var one = List[UInt64]()
    one.append(UInt64(1))
    one.append(UInt64(0))
    one.append(UInt64(0))
    one.append(UInt64(0))
    return JacobianPoint(p.x.copy(), p.y.copy(), one^, False)


fn jacobian_to_affine(p: JacobianPoint) -> ECPoint:
    if p.infinity:
        return point_infinity()
    var mod = p256_p()
    var z_inv = mod_inv(p.z, mod)
    var z2 = mod_mul(z_inv, z_inv, mod)
    var x = mod_mul(p.x, z2, mod)
    var y = mod_mul(p.y, mod_mul(z2, z_inv, mod), mod)
    return ECPoint(x^, y^, False)


fn jacobian_double(p: JacobianPoint) -> JacobianPoint:
    if p.infinity:
        return p.clone()
    var mod = p256_p()
    var two = u256_const(UInt64(2))
    var three = u256_const(UInt64(3))
    var a = sub_mod(mod, three, mod)
    var xx = mod_mul(p.x, p.x, mod)
    var yy = mod_mul(p.y, p.y, mod)
    var yyyy = mod_mul(yy, yy, mod)
    var zz = mod_mul(p.z, p.z, mod)
    var s = mod_mul(
        two,
        sub_mod(
            sub_mod(
                mod_mul(add_mod(p.x, yy, mod), add_mod(p.x, yy, mod), mod),
                xx,
                mod,
            ),
            yyyy,
            mod,
        ),
        mod,
    )
    var m = add_mod(
        mod_mul(three, xx, mod), mod_mul(a, mod_mul(zz, zz, mod), mod), mod
    )
    var t = mod_mul(m, m, mod)
    var x3 = sub_mod(sub_mod(t, s, mod), s, mod)
    var y3 = sub_mod(
        mod_mul(m, sub_mod(s, x3, mod), mod),
        mod_mul(u256_const(UInt64(8)), yyyy, mod),
        mod,
    )
    var z3 = mod_mul(two, mod_mul(p.y, p.z, mod), mod)
    return JacobianPoint(x3^, y3^, z3^, False)


fn jacobian_add(p: JacobianPoint, q: JacobianPoint) -> JacobianPoint:
    if p.infinity:
        return q.clone()
    if q.infinity:
        return p.clone()
    var mod = p256_p()
    var z1z1 = mod_mul(p.z, p.z, mod)
    var z2z2 = mod_mul(q.z, q.z, mod)
    var u1 = mod_mul(p.x, z2z2, mod)
    var u2 = mod_mul(q.x, z1z1, mod)
    var s1 = mod_mul(p.y, mod_mul(q.z, z2z2, mod), mod)
    var s2 = mod_mul(q.y, mod_mul(p.z, z1z1, mod), mod)
    var h = sub_mod(u2, u1, mod)
    var r = sub_mod(s2, s1, mod)
    if is_zero(h):
        if is_zero(r):
            return jacobian_double(p)
        return jacobian_infinity()
    var h2 = mod_mul(h, h, mod)
    var h3 = mod_mul(h2, h, mod)
    var u1h2 = mod_mul(u1, h2, mod)
    var two = u256_const(UInt64(2))
    var x3 = sub_mod(
        sub_mod(mod_mul(r, r, mod), h3, mod), mod_mul(two, u1h2, mod), mod
    )
    var y3 = sub_mod(
        mod_mul(r, sub_mod(u1h2, x3, mod), mod), mod_mul(s1, h3, mod), mod
    )
    var z3 = mod_mul(h, mod_mul(p.z, q.z, mod), mod)
    return JacobianPoint(x3^, y3^, z3^, False)


fn point_add(p: ECPoint, q: ECPoint) -> ECPoint:
    if p.infinity:
        return q.clone()
    if q.infinity:
        return p.clone()
    var mod = p256_p()
    if cmp_limbs(p.x, q.x) == 0:
        var y_sum = add_mod(p.y, q.y, mod)
        if is_zero(y_sum):
            return point_infinity()
        return point_double(p)
    var y_diff = sub_mod(q.y, p.y, mod)
    var x_diff = sub_mod(q.x, p.x, mod)
    var lam = mod_mul(y_diff, mod_inv(x_diff, mod), mod)
    var x3 = sub_mod(sub_mod(mod_mul(lam, lam, mod), p.x, mod), q.x, mod)
    var y3 = sub_mod(mod_mul(lam, sub_mod(p.x, x3, mod), mod), p.y, mod)
    return ECPoint(x3^, y3^, False)


fn point_double(p: ECPoint) -> ECPoint:
    if p.infinity:
        return p.clone()
    var mod = p256_p()
    var three = List[UInt64]()
    three.append(UInt64(3))
    three.append(UInt64(0))
    three.append(UInt64(0))
    three.append(UInt64(0))
    var two = List[UInt64]()
    two.append(UInt64(2))
    two.append(UInt64(0))
    two.append(UInt64(0))
    two.append(UInt64(0))
    var a = sub_mod(mod, three, mod)  # -3 mod p
    var num = add_mod(mod_mul(three, mod_mul(p.x, p.x, mod), mod), a, mod)
    var den = mod_mul(two, p.y, mod)
    if is_zero(den):
        return point_infinity()
    var lam = mod_mul(num, mod_inv(den, mod), mod)
    var x3 = sub_mod(mod_mul(lam, lam, mod), mod_mul(two, p.x, mod), mod)
    var y3 = sub_mod(mod_mul(lam, sub_mod(p.x, x3, mod), mod), p.y, mod)
    return ECPoint(x3^, y3^, False)


fn scalar_mul(k: List[UInt64], p: ECPoint) -> ECPoint:
    var result = jacobian_infinity()
    var addend = jacobian_from_affine(p)
    var i = 0
    while i < 256:
        if ((k[i // 64] >> (i % 64)) & UInt64(1)) == UInt64(1):
            result = jacobian_add(result, addend)
        addend = jacobian_double(addend)
        i += 1
    return jacobian_to_affine(result)


fn parse_ecdsa_signature(
    sig_der: List[UInt8],
) raises -> (List[UInt64], List[UInt64]):
    var reader = DerReader(sig_der)
    var seq = read_sequence_reader(reader)
    var r_bytes = read_integer_bytes(seq)
    var s_bytes = read_integer_bytes(seq)
    return (u256_from_be(r_bytes), u256_from_be(s_bytes))


fn verify_ecdsa_p256_hash(
    pubkey: List[UInt8], hash: List[UInt8], sig_der: List[UInt8]
) raises -> Bool:
    if len(pubkey) != 65:
        return False
    if pubkey[0] != UInt8(0x04):
        return False
    var x_bytes = List[UInt8]()
    var y_bytes = List[UInt8]()
    var i = 1
    while i < 33:
        x_bytes.append(pubkey[i])
        i += 1
    while i < 65:
        y_bytes.append(pubkey[i])
        i += 1
    var q = ECPoint(u256_from_be(x_bytes), u256_from_be(y_bytes), False)
    var parsed = parse_ecdsa_signature(sig_der)
    var r = parsed[0].copy()
    var s = parsed[1].copy()
    var n = p256_n()
    if is_zero(r) or is_zero(s):
        return False
    if cmp_limbs(r, n) >= 0 or cmp_limbs(s, n) >= 0:
        return False
    var digest = hash.copy()
    if len(digest) > 32:
        var truncated = List[UInt8]()
        var i = 0
        while i < 32:
            truncated.append(digest[i])
            i += 1
        digest = truncated^
    var e = u256_from_be(digest)
    var w = mod_inv(s, n)
    var u1 = mod_mul(e, w, n)
    var u2 = mod_mul(r, w, n)
    var g = ECPoint(p256_gx(), p256_gy(), False)
    var p1 = scalar_mul(u1, g)
    var p2 = scalar_mul(u2, q)
    var x = point_add(p1, p2).x.copy()
    var v = mod_reduce(x, n)
    return cmp_limbs(v, r) == 0


fn verify_ecdsa_p256(
    pubkey: List[UInt8], msg: List[UInt8], sig_der: List[UInt8]
) raises -> Bool:
    return verify_ecdsa_p256_hash(pubkey, sha256_bytes(msg), sig_der)
