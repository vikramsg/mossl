from collections import List
from pki.bigint import BigInt, mod_pow, mod_inv, mod_mul, add_mod, sub_mod, cmp_limbs, mod_reduce, add_limbs, sub_limbs, mul_limbs
from pki.asn1 import DerReader, read_sequence_reader, read_integer_bytes
from crypto.bytes import hex_to_bytes
from crypto.sha384 import sha384_bytes

fn p384_p() -> List[UInt64]:
    return BigInt(hex_to_bytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff")).limbs.copy()

fn p384_n() -> List[UInt64]:
    return BigInt(hex_to_bytes("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973")).limbs.copy()

fn p384_gx() -> List[UInt64]:
    return BigInt(hex_to_bytes("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7")).limbs.copy()

fn p384_gy() -> List[UInt64]:
    return BigInt(hex_to_bytes("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")).limbs.copy()

@fieldwise_init
struct ECPoint384(Movable):
    var x: List[UInt64]
    var y: List[UInt64]
    var infinity: Bool

    fn clone(self) -> ECPoint384:
        return ECPoint384(self.x.copy(), self.y.copy(), self.infinity)

@fieldwise_init
struct JacobianPoint384(Movable):
    var x: List[UInt64]
    var y: List[UInt64]
    var z: List[UInt64]
    var infinity: Bool

    fn clone(self) -> JacobianPoint384:
        return JacobianPoint384(self.x.copy(), self.y.copy(), self.z.copy(), self.infinity)

fn jacobian_double(p: JacobianPoint384) -> JacobianPoint384:
    if p.infinity or (len(p.y) == 1 and p.y[0] == 0):
        var zero = List[UInt64](); zero.append(0)
        return JacobianPoint384(zero.copy(), zero.copy(), zero.copy(), True)
    
    var mod = p384_p()
    var three = List[UInt64](); three.append(3)
    var two = List[UInt64](); two.append(2)
    var eight = List[UInt64](); eight.append(8)
    
    var x2 = mod_mul(p.x, p.x, mod)
    var z2 = mod_mul(p.z, p.z, mod)
    var z4 = mod_mul(z2, z2, mod)
    var m = mod_mul(three, sub_mod(x2, z4, mod), mod)
    
    var y2 = mod_mul(p.y, p.y, mod)
    var s = mod_mul(mod_mul(List[UInt64]([4]), p.x, mod), y2, mod)
    var t = mod_mul(eight, mod_mul(y2, y2, mod), mod)
    
    var x3 = sub_mod(mod_mul(m, m, mod), mod_mul(two, s, mod), mod)
    var y3 = sub_mod(mod_mul(m, sub_mod(s, x3, mod), mod), t, mod)
    var z3 = mod_mul(two, mod_mul(p.y, p.z, mod), mod)
    
    return JacobianPoint384(x3.copy(), y3.copy(), z3.copy(), False)

fn jacobian_add(p: JacobianPoint384, q: JacobianPoint384) -> JacobianPoint384:
    if p.infinity: return q.clone()
    if q.infinity: return p.clone()
    
    var mod = p384_p()
    var z1z1 = mod_mul(p.z, p.z, mod)
    var z2z2 = mod_mul(q.z, q.z, mod)
    
    var u1 = mod_mul(p.x, z2z2, mod)
    var u2 = mod_mul(q.x, z1z1, mod)
    var s1 = mod_mul(p.y, mod_mul(q.z, z2z2, mod), mod)
    var s2 = mod_mul(q.y, mod_mul(p.z, z1z1, mod), mod)
    
    if cmp_limbs(u1, u2) == 0:
        if cmp_limbs(s1, s2) == 0:
            return jacobian_double(p)
        else:
            var zero = List[UInt64](); zero.append(0)
            return JacobianPoint384(zero.copy(), zero.copy(), zero.copy(), True)
            
    var h = sub_mod(u2, u1, mod)
    var r = sub_mod(s2, s1, mod)
    var h2 = mod_mul(h, h, mod)
    var h3 = mod_mul(h, h2, mod)
    var u1h2 = mod_mul(u1, h2, mod)
    
    var x3 = sub_mod(sub_mod(mod_mul(r, r, mod), h3, mod), mod_mul(List[UInt64]([2]), u1h2, mod), mod)
    var y3 = sub_mod(mod_mul(r, sub_mod(u1h2, x3, mod), mod), mod_mul(s1, h3, mod), mod)
    var z3 = mod_mul(h, mod_mul(p.z, q.z, mod), mod)
    
    return JacobianPoint384(x3.copy(), y3.copy(), z3.copy(), False)

fn jacobian_to_affine(p: JacobianPoint384) -> ECPoint384:
    if p.infinity:
        var zero = List[UInt64](); zero.append(0)
        return ECPoint384(zero.copy(), zero.copy(), True)
    var mod = p384_p()
    var zinv = mod_inv(p.z, mod)
    var zinv2 = mod_mul(zinv, zinv, mod)
    var x = mod_mul(p.x, zinv2, mod)
    var y = mod_mul(p.y, mod_mul(zinv2, zinv, mod), mod)
    return ECPoint384(x.copy(), y.copy(), False)

fn scalar_mul(k: List[UInt64], p: ECPoint384) -> ECPoint384:
    var res = JacobianPoint384(List[UInt64]([0]), List[UInt64]([0]), List[UInt64]([0]), True)
    var temp = JacobianPoint384(p.x.copy(), p.y.copy(), List[UInt64]([1]), False)
    
    for i in range(384):
        var limb = i // 64
        var bit = i % 64
        if limb < len(k):
            if ((k[limb] >> bit) & 1) == 1:
                res = jacobian_add(res, temp)
        temp = jacobian_double(temp)
    return jacobian_to_affine(res)

fn verify_ecdsa_p384_hash(pubkey: List[UInt8], hash: List[UInt8], sig_der: List[UInt8]) raises -> Bool:
    if len(pubkey) != 97 or pubkey[0] != 0x04: return False
    var x_bytes = List[UInt8](); var y_bytes = List[UInt8]()
    for i in range(1, 49): x_bytes.append(pubkey[i])
    for i in range(49, 97): y_bytes.append(pubkey[i])
    
    var q = ECPoint384(BigInt(x_bytes).limbs.copy(), BigInt(y_bytes).limbs.copy(), False)
    
    var reader = DerReader(sig_der)
    var seq = read_sequence_reader(reader)
    var r_bytes = read_integer_bytes(seq)
    var s_bytes = read_integer_bytes(seq)
    var r = BigInt(r_bytes).limbs.copy()
    var s = BigInt(s_bytes).limbs.copy()
    
    var n = p384_n()
    if BigInt(r).is_zero() or BigInt(s).is_zero(): return False
    if cmp_limbs(r, n) >= 0 or cmp_limbs(s, n) >= 0: return False
    
    var e = BigInt(hash).limbs.copy()
    var w = mod_inv(s.copy(), n.copy())
    var u1 = mod_mul(e.copy(), w.copy(), n.copy())
    var u2 = mod_mul(r.copy(), w.copy(), n.copy())
    
    var g = ECPoint384(p384_gx(), p384_gy(), False)
    var p1 = scalar_mul(u1.copy(), g)
    var p2 = scalar_mul(u2.copy(), q)
    
    var res_j = jacobian_add(JacobianPoint384(p1.x.copy(), p1.y.copy(), List[UInt64]([1]), False),
                             JacobianPoint384(p2.x.copy(), p2.y.copy(), List[UInt64]([1]), False))
    var res = jacobian_to_affine(res_j)
    
    var v = mod_reduce(res.x.copy(), n.copy())
    return cmp_limbs(v, r) == 0