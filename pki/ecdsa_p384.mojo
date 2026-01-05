from collections import List

from pki.asn1 import DerReader, read_sequence_reader, read_integer_bytes

from crypto.bytes import hex_to_bytes
from crypto.sha384 import sha384_bytes

from pki.bigint import (
    BigInt,
    mod_inv,
    mod_mul,
    add_mod,
    sub_mod,
    cmp_limbs,
    mod_reduce,
)


fn p384_p() -> List[UInt64]:
    return BigInt.from_be_bytes(
        hex_to_bytes(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"
        )
    ).limbs.copy()


fn p384_n() -> List[UInt64]:
    return BigInt.from_be_bytes(
        hex_to_bytes(
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
        )
    ).limbs.copy()


fn p384_gx() -> List[UInt64]:
    return BigInt.from_be_bytes(
        hex_to_bytes(
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
        )
    ).limbs.copy()


fn p384_gy() -> List[UInt64]:
    return BigInt.from_be_bytes(
        hex_to_bytes(
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
        )
    ).limbs.copy()


@fieldwise_init
struct ECPoint384(Movable):
    var x: List[UInt64]
    var y: List[UInt64]
    var infinity: Bool

    fn copy(self) -> ECPoint384:
        return ECPoint384(self.x.copy(), self.y.copy(), self.infinity)


@fieldwise_init
struct ECPoint384Jac(Movable):
    var x: List[UInt64]
    var y: List[UInt64]
    var z: List[UInt64]

    fn is_infinity(self) -> Bool:
        return BigInt(self.z).is_zero()

    fn copy(self) -> ECPoint384Jac:
        return ECPoint384Jac(self.x.copy(), self.y.copy(), self.z.copy())


fn small_limbs(v: UInt64) -> List[UInt64]:
    var out = List[UInt64]()
    out.append(v)
    return out^


fn jacobian_from_affine(p: ECPoint384) -> ECPoint384Jac:
    if p.infinity:
        return ECPoint384Jac(List[UInt64](), List[UInt64](), List[UInt64]())
    var one = small_limbs(1)
    return ECPoint384Jac(p.x.copy(), p.y.copy(), one^)


fn jacobian_to_affine(p: ECPoint384Jac) -> ECPoint384:
    if p.is_infinity():
        return ECPoint384(List[UInt64](), List[UInt64](), True)
    var mod = p384_p()
    var z_inv = mod_inv(p.z.copy(), mod)
    var z2 = mod_mul(z_inv.copy(), z_inv.copy(), mod)
    var z3 = mod_mul(z2.copy(), z_inv, mod)
    var x = mod_mul(p.x.copy(), z2, mod)
    var y = mod_mul(p.y.copy(), z3, mod)
    return ECPoint384(x^, y^, False)


fn jacobian_double(p: ECPoint384Jac) -> ECPoint384Jac:
    if p.is_infinity():
        return p.copy()
    if BigInt(p.y).is_zero():
        return ECPoint384Jac(List[UInt64](), List[UInt64](), List[UInt64]())
    var mod = p384_p()

    var two = small_limbs(2)
    var three = small_limbs(3)
    var four = small_limbs(4)
    var eight = small_limbs(8)

    var y2 = mod_mul(p.y.copy(), p.y.copy(), mod)
    var s = mod_mul(four, mod_mul(p.x.copy(), y2.copy(), mod), mod)

    var z2 = mod_mul(p.z.copy(), p.z.copy(), mod)
    var x_minus = sub_mod(p.x.copy(), z2.copy(), mod)
    var x_plus = add_mod(p.x.copy(), z2.copy(), mod)
    var m = mod_mul(three, mod_mul(x_minus, x_plus, mod), mod)

    var x3 = sub_mod(
        sub_mod(mod_mul(m.copy(), m.copy(), mod), s.copy(), mod), s.copy(), mod
    )
    var y4 = mod_mul(y2.copy(), y2.copy(), mod)
    var y3 = sub_mod(
        mod_mul(m, sub_mod(s, x3.copy(), mod), mod),
        mod_mul(eight, y4, mod),
        mod,
    )
    var z3 = mod_mul(two, mod_mul(p.y, p.z, mod), mod)

    return ECPoint384Jac(x3^, y3^, z3^)


fn jacobian_add(p: ECPoint384Jac, q: ECPoint384Jac) -> ECPoint384Jac:
    if p.is_infinity():
        return q.copy()
    if q.is_infinity():
        return p.copy()
    var mod = p384_p()

    var z1z1 = mod_mul(p.z.copy(), p.z.copy(), mod)
    var z2z2 = mod_mul(q.z.copy(), q.z.copy(), mod)
    var u1 = mod_mul(p.x.copy(), z2z2.copy(), mod)
    var u2 = mod_mul(q.x.copy(), z1z1.copy(), mod)
    var s1 = mod_mul(p.y.copy(), mod_mul(q.z.copy(), z2z2, mod), mod)
    var s2 = mod_mul(q.y.copy(), mod_mul(p.z.copy(), z1z1, mod), mod)

    var h = sub_mod(u2.copy(), u1.copy(), mod)
    var r = sub_mod(s2.copy(), s1.copy(), mod)
    if BigInt(h).is_zero():
        if BigInt(r).is_zero():
            return jacobian_double(p)
        return ECPoint384Jac(List[UInt64](), List[UInt64](), List[UInt64]())

    var hh = mod_mul(h.copy(), h.copy(), mod)
    var hhh = mod_mul(h.copy(), hh.copy(), mod)
    var v = mod_mul(u1, hh.copy(), mod)

    var x3 = sub_mod(
        sub_mod(mod_mul(r.copy(), r.copy(), mod), hhh.copy(), mod),
        add_mod(v.copy(), v.copy(), mod),
        mod,
    )
    var y3 = sub_mod(
        mod_mul(r, sub_mod(v, x3.copy(), mod), mod), mod_mul(s1, hhh, mod), mod
    )
    var z3 = mod_mul(h, mod_mul(p.z, q.z, mod), mod)

    return ECPoint384Jac(x3^, y3^, z3^)


fn point_add(p: ECPoint384, q: ECPoint384) -> ECPoint384:
    if p.infinity:
        return q.copy()
    if q.infinity:
        return p.copy()
    var mod = p384_p()
    if cmp_limbs(p.x, q.x) == 0:
        if cmp_limbs(p.y, q.y) == 0:
            return point_double(p)
        return ECPoint384(List[UInt64](), List[UInt64](), True)

    # lambda = (y2 - y1) / (x2 - x1)
    var num = sub_mod(q.y.copy(), p.y.copy(), mod)
    var den = sub_mod(q.x.copy(), p.x.copy(), mod)
    var l = mod_mul(num, mod_inv(den, mod), mod)

    # x3 = l^2 - x1 - x2
    var x3 = sub_mod(
        sub_mod(mod_mul(l.copy(), l.copy(), mod), p.x.copy(), mod),
        q.x.copy(),
        mod,
    )
    # y3 = l(x1 - x3) - y1
    var y3 = sub_mod(
        mod_mul(l, sub_mod(p.x.copy(), x3.copy(), mod), mod), p.y.copy(), mod
    )

    var res = ECPoint384(x3^, y3^, False)
    return res^


fn point_double(p: ECPoint384) -> ECPoint384:
    if p.infinity:
        return p.copy()
    var mod = p384_p()
    var three = List[UInt64]()
    three.append(3)
    var two = List[UInt64]()
    two.append(2)
    # lambda = (3x^2 + a) / 2y, a = -3
    var a = sub_mod(mod, three, mod)
    var num = add_mod(
        mod_mul(three, mod_mul(p.x.copy(), p.x.copy(), mod), mod), a, mod
    )
    var den = mod_mul(two, p.y.copy(), mod)
    var l = mod_mul(num, mod_inv(den, mod), mod)

    var x3 = sub_mod(
        sub_mod(mod_mul(l.copy(), l.copy(), mod), p.x.copy(), mod),
        p.x.copy(),
        mod,
    )
    var y3 = sub_mod(
        mod_mul(l, sub_mod(p.x.copy(), x3.copy(), mod), mod), p.y.copy(), mod
    )

    var res = ECPoint384(x3^, y3^, False)
    return res^


fn scalar_mul(k: List[UInt64], p: ECPoint384) -> ECPoint384:
    var res = ECPoint384Jac(List[UInt64](), List[UInt64](), List[UInt64]())
    var temp = jacobian_from_affine(p)
    var bits = BigInt(k).bit_length()
    for i in range(bits):
        var limb = i // 64
        var bit = i % 64
        if ((k[limb] >> bit) & 1) == 1:
            res = jacobian_add(res, temp)
        temp = jacobian_double(temp)
    return jacobian_to_affine(res)


fn verify_ecdsa_p384_hash(
    pubkey: List[UInt8], hash: List[UInt8], sig_der: List[UInt8]
) raises -> Bool:
    if len(pubkey) != 97 or pubkey[0] != 0x04:
        return False
    var x_bytes = List[UInt8]()
    var y_bytes = List[UInt8]()
    for i in range(1, 49):
        x_bytes.append(pubkey[i])
    for i in range(49, 97):
        y_bytes.append(pubkey[i])
    var q = ECPoint384(
        BigInt.from_be_bytes(x_bytes).limbs.copy(),
        BigInt.from_be_bytes(y_bytes).limbs.copy(),
        False,
    )
    var reader = DerReader(sig_der)
    var seq = read_sequence_reader(reader)
    var r_bytes = read_integer_bytes(seq)
    var s_bytes = read_integer_bytes(seq)
    var r = BigInt.from_be_bytes(r_bytes).limbs.copy()
    var s = BigInt.from_be_bytes(s_bytes).limbs.copy()
    var n = p384_n()
    if BigInt(r).is_zero() or BigInt(s).is_zero():
        return False
    if cmp_limbs(r, n) >= 0 or cmp_limbs(s, n) >= 0:
        return False
    var e = BigInt.from_be_bytes(hash).limbs.copy()
    var w = mod_inv(s.copy(), n.copy())
    var u1 = mod_mul(e.copy(), w.copy(), n.copy())
    var u2 = mod_mul(r.copy(), w.copy(), n.copy())
    var g = ECPoint384(p384_gx(), p384_gy(), False)
    var p1 = scalar_mul(u1.copy(), g)
    var p2 = scalar_mul(u2.copy(), q)
    var res = point_add(p1, p2)
    var v = mod_reduce(res.x.copy(), n.copy())
    return cmp_limbs(v, r) == 0
