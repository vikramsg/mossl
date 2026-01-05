from collections import List
from pki.bigint import BigInt, mod_pow, mod_inv, mod_mul, add_mod, sub_mod, cmp_limbs, mod_reduce, add_limbs, sub_limbs, mul_limbs
from pki.asn1 import DerReader, read_sequence_reader, read_integer_bytes
from crypto.bytes import hex_to_bytes, bytes_to_hex
from crypto.sha384 import sha384_bytes

fn p384_p() -> List[UInt64]:
    return BigInt.from_be_bytes(hex_to_bytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff")).limbs.copy()

fn p384_n() -> List[UInt64]:
    return BigInt.from_be_bytes(hex_to_bytes("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973")).limbs.copy()

fn p384_gx() -> List[UInt64]:
    return BigInt.from_be_bytes(hex_to_bytes("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7")).limbs.copy()

fn p384_gy() -> List[UInt64]:
    return BigInt.from_be_bytes(hex_to_bytes("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")).limbs.copy()

@fieldwise_init
struct ECPoint384(Movable):
    var x: List[UInt64]
    var y: List[UInt64]
    var infinity: Bool

    fn copy(self) -> ECPoint384:
        return ECPoint384(self.x.copy(), self.y.copy(), self.infinity)

fn point_add(p: ECPoint384, q: ECPoint384) -> ECPoint384:
    if p.infinity: return q.copy()
    if q.infinity: return p.copy()
    var mod = p384_p()
    if cmp_limbs(p.x, q.x) == 0:
        if cmp_limbs(p.y, q.y) == 0: return point_double(p)
        return ECPoint384(List[UInt64](), List[UInt64](), True)
    
    # lambda = (y2 - y1) / (x2 - x1)
    var num = sub_mod(q.y.copy(), p.y.copy(), mod)
    var den = sub_mod(q.x.copy(), p.x.copy(), mod)
    var l = mod_mul(num, mod_inv(den, mod), mod)
    
    # x3 = l^2 - x1 - x2
    var x3 = sub_mod(sub_mod(mod_mul(l.copy(), l.copy(), mod), p.x.copy(), mod), q.x.copy(), mod)
    # y3 = l(x1 - x3) - y1
    var y3 = sub_mod(mod_mul(l, sub_mod(p.x.copy(), x3.copy(), mod), mod), p.y.copy(), mod)
    
    var res = ECPoint384(x3, y3, False)
    print("  point_add debug:")
    print("    l:  " + bytes_to_hex(BigInt(l).to_be_bytes(48)))
    print("    x3: " + bytes_to_hex(BigInt(x3).to_be_bytes(48)))
    return res.copy()

fn point_double(p: ECPoint384) -> ECPoint384:
    if p.infinity: return p.copy()
    var mod = p384_p()
    var three = List[UInt64](); three.append(3)
    var two = List[UInt64](); two.append(2)
    # lambda = (3x^2 + a) / 2y, a = -3
    var a = sub_mod(mod, three, mod)
    var num = add_mod(mod_mul(three, mod_mul(p.x.copy(), p.x.copy(), mod), mod), a, mod)
    var den = mod_mul(two, p.y.copy(), mod)
    var l = mod_mul(num, mod_inv(den, mod), mod)
    
    var x3 = sub_mod(sub_mod(mod_mul(l.copy(), l.copy(), mod), p.x.copy(), mod), p.x.copy(), mod)
    var y3 = sub_mod(mod_mul(l, sub_mod(p.x.copy(), x3.copy(), mod), mod), p.y.copy(), mod)
    
    var res = ECPoint384(x3, y3, False)
    print("  point_double debug:")
    print("    num: " + bytes_to_hex(BigInt(num).to_be_bytes(48)))
    print("    den: " + bytes_to_hex(BigInt(den).to_be_bytes(48)))
    print("    l:   " + bytes_to_hex(BigInt(l).to_be_bytes(48)))
    print("    x3:  " + bytes_to_hex(BigInt(x3).to_be_bytes(48)))
    return res.copy()


fn scalar_mul(k: List[UInt64], p: ECPoint384) -> ECPoint384:
    var res = ECPoint384(List[UInt64](), List[UInt64](), True)
    var temp = p.copy()
    var bits = BigInt(k).bit_length()
    for i in range(bits):
        var limb = i // 64
        var bit = i % 64
        if ((k[limb] >> bit) & 1) == 1:
            res = point_add(res, temp)
        temp = point_double(temp)
    return res^

fn verify_ecdsa_p384_hash(pubkey: List[UInt8], hash: List[UInt8], sig_der: List[UInt8]) raises -> Bool:
    if len(pubkey) != 97 or pubkey[0] != 0x04: return False
    var x_bytes = List[UInt8](); var y_bytes = List[UInt8]()
    for i in range(1, 49): x_bytes.append(pubkey[i])
    for i in range(49, 97): y_bytes.append(pubkey[i])
    var q = ECPoint384(BigInt.from_be_bytes(x_bytes).limbs.copy(), BigInt.from_be_bytes(y_bytes).limbs.copy(), False)
    var reader = DerReader(sig_der)
    var seq = read_sequence_reader(reader)
    var r_bytes = read_integer_bytes(seq)
    var s_bytes = read_integer_bytes(seq)
    var r = BigInt.from_be_bytes(r_bytes).limbs.copy()
    var s = BigInt.from_be_bytes(s_bytes).limbs.copy()
    var n = p384_n()
    if BigInt(r).is_zero() or BigInt(s).is_zero(): return False
    if cmp_limbs(r, n) >= 0 or cmp_limbs(s, n) >= 0: return False
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