from collections import List, InlineArray
from testing import assert_equal
from time import perf_counter

from memory import UnsafePointer
from pki.bigint import BigInt, add_limbs, sub_limbs, mul_limbs, mod_pow, cmp_limbs, montgomery_n0_inv

from crypto.bytes import hex_to_bytes

# BigInt Generic Implementation using Mojo Comptime Parameters
#
# This implementation uses a parameter `limbs` to define the size of the BigInt
# at compile-time. This allows the compiler to optimize for specific sizes
# while maintaining a single, generic codebase.

struct BigIntGeneric[limbs: Int](Copyable, Movable):
    var data: InlineArray[UInt64, limbs]

    fn __init__(out self):
        self.data = InlineArray[UInt64, limbs](0)

    fn __init__(out self, data: InlineArray[UInt64, limbs]):
        self.data = data

    fn __copyinit__(out self, other: BigIntGeneric[limbs]):
        self.data = other.data

    fn __moveinit__(out self, deinit other: BigIntGeneric[limbs]):
        self.data = other.data

    fn copy(self) -> BigIntGeneric[limbs]:
        return BigIntGeneric[limbs](self.data)

    @staticmethod
    fn from_list(l: List[UInt64]) -> BigIntGeneric[limbs]:
        var res = BigIntGeneric[limbs]()
        for i in range(min(len(l), limbs)):
            res.data[i] = l[i]
        return res^

    fn montgomery_mul(self, other: BigIntGeneric[limbs], mod: BigIntGeneric[limbs], n0_inv: UInt64) -> BigIntGeneric[limbs]:
        # Temporary array for multiplication result (2*limbs + 1 for carry)
        # Using alias for compile-time calculation of temporary size
        alias temp_size = limbs * 2 + 1
        var t = InlineArray[UInt64, temp_size](0)
        
        # Multiply
        for i in range(limbs):
            var carry = UInt128(0)
            var ai = UInt128(self.data[i])
            for j in range(limbs):
                var prod = ai * UInt128(other.data[j]) + UInt128(t[i + j]) + carry
                t[i + j] = UInt64(prod & 0xFFFFFFFFFFFFFFFF)
                carry = prod >> 64
            t[i + limbs] = UInt64(carry)
            
        # Reduce
        for i in range(limbs):
            var m = UInt64((UInt128(t[i]) * UInt128(n0_inv)) & 0xFFFFFFFFFFFFFFFF)
            var carry = UInt128(0)
            for j in range(limbs):
                var idx = i + j
                var prod = UInt128(m) * UInt128(mod.data[j]) + UInt128(t[idx]) + carry
                t[idx] = UInt64(prod & 0xFFFFFFFFFFFFFFFF)
                carry = prod >> 64
            
            var idx2 = i + limbs
            var sum = UInt128(t[idx2]) + carry
            t[idx2] = UInt64(sum & 0xFFFFFFFFFFFFFFFF)
            var carry2 = UInt64(sum >> 64)
            if carry2 > 0:
                t[idx2 + 1] = UInt64(UInt128(t[idx2 + 1]) + UInt128(carry2))

        var res = BigIntGeneric[limbs]()
        for i in range(limbs):
            res.data[i] = t[i + limbs]
            
        # Final subtraction if res >= mod
        # (Simplified: in production we need constant-time or careful comparison)
        var ge = True
        for i in range(limbs - 1, -1, -1):
            if res.data[i] > mod.data[i]:
                break
            if res.data[i] < mod.data[i]:
                ge = False
                break
        
        if ge:
            var borrow = UInt128(0)
            for i in range(limbs):
                var diff = UInt128(res.data[i]) - UInt128(mod.data[i]) - borrow
                if diff > 0xFFFFFFFFFFFFFFFF:
                    res.data[i] = UInt64(diff & 0xFFFFFFFFFFFFFFFF)
                    borrow = 1
                else:
                    res.data[i] = UInt64(diff)
                    borrow = 0
                    
        return res^

fn benchmark_generic_384():
    print("Benchmarking Generic BigInt (384-bit)...")
    alias L384 = 6
    var a_bytes = List[UInt8]()
    for _ in range(48): a_bytes.append(0xFF)
    var mod_bytes = List[UInt8]()
    for _ in range(47): mod_bytes.append(0xEE)
    mod_bytes.append(0xEF)
    var exp_bytes = List[UInt8]()
    for _ in range(48): exp_bytes.append(0xDD)
    
    var a_bi = BigInt.from_be_bytes(a_bytes^)
    var a_l = a_bi.limbs.copy()
    var mod_bi = BigInt.from_be_bytes(mod_bytes^)
    var mod_l = mod_bi.limbs.copy()
    var exp_bi = BigInt.from_be_bytes(exp_bytes^)
    var exp_l = exp_bi.limbs.copy()
    
    var a = BigIntGeneric[L384].from_list(a_l)
    var mod = BigIntGeneric[L384].from_list(mod_l)
    var exp = BigIntGeneric[L384].from_list(exp_l)
    var n0_inv = montgomery_n0_inv(mod.data[0])
    
    var start = perf_counter()
    var iters = 100
    for _ in range(iters):
        var res = BigIntGeneric[L384]()
        res.data[0] = 1
        var b = a.copy()
        for i in range(384):
            var limb_idx = i // 64
            var bit_idx = i % 64
            if (exp.data[limb_idx] >> bit_idx) & 1:
                res = res.montgomery_mul(b, mod, n0_inv)
            b = b.montgomery_mul(b, mod, n0_inv)
    var end = perf_counter()
    print("Generic BigInt6 mod_pow:", iters / (end - start), "ops/sec")

fn benchmark_generic_2048():
    print("Benchmarking Generic BigInt (2048-bit)...")
    alias L2048 = 32
    var n_hex = "e207016f182663eb143905a473fcd2b4ad71f46bc8460e81a42c58a0727de3d9332b4708f828fa232f47b3abfc6b019971e4f3c02ee19910a79c0281a80151820ed3d46003bf4a81b4f87f10fc6305a711730940bb5925d3eaa55e30a40297a5f2e51c2eb23cc793d21dd7f2df877bb04c6b724e008300ac88dd1ed1d7971c9ec4927febe8d8037ef46e49b59a411c61c7192bfc62db6a638905faf4c67fbd86cc8d3fc241e71496cb63b6f3e7bfb98d0df252152c6aeefdac023eab340e76a2ca4f2d4219720c4b1cb39c14cbd69a2048e3320c8232e8c63d5b7dee07a4747dead4fb2d2aee1ff5b908bd9005ac33fc431fce97ccd0e7862d47f7449947698f"
    _ = "10001" 
    var s_hex = "95a9fc52806c68693b153b345c6b7f5083a5dbccfd3b2669796f8c63c6537e916ebe1fc1a285ccb4867ed13023bdb0ef7ae471a33c7c78fdfeee5d44e6fcf171e8e1f8dcb0e6c8c7bc6aa36ae3e1ac1d7f1341b7e813898175f824a8e4472681b2ab77413c93119d21be0d0a95ad1e2209cbd6358416c6ce7787e8fac2cedb52b9fb975e509fe206218d1359d3314f38be80fab8af7830e5174409db134b1e9762d33bac354b8a86376d9a7b6e125f45351789a6de46e1f062ae2406bef5e939f31db804deadd0afb4104ac6ea5bfa153f5629ef642118fe4259464a8b2ce26e9844f4d2434463a417d726d9e17eef55312c4b4d0e19f6177ee7070251870cf4"

    var n_bi = BigInt.from_be_bytes(hex_to_bytes(n_hex))
    var n_l = n_bi.limbs.copy()
    var s_bi = BigInt.from_be_bytes(hex_to_bytes(s_hex))
    var s_l = s_bi.limbs.copy()
    
    var n = BigIntGeneric[L2048].from_list(n_l)
    var s = BigIntGeneric[L2048].from_list(s_l)
    var n0_inv = montgomery_n0_inv(n.data[0])
    
    # R2 mod N calculation
    from pki.bigint import shift_left, mod_reduce, mul_limbs
    var r_list = List[UInt64]()
    r_list.append(1)
    var r_shifted = shift_left(r_list^, 64 * L2048)
    var r_mod_val = mod_reduce(r_shifted^, n_l)
    var r2_l = mod_reduce(mul_limbs(r_mod_val.copy(), r_mod_val), n_l)
    var r2 = BigIntGeneric[L2048].from_list(r2_l)
    var one = BigIntGeneric[L2048]()
    one.data[0] = 1
    
    var res_m = one.montgomery_mul(r2, n, n0_inv)
    var b_m = s.montgomery_mul(r2, n, n0_inv)
    
    var start = perf_counter()
    var iters = 100
    for _ in range(iters):
        var cur_res_m = res_m.copy()
        var cur_b_m = b_m.copy()
        for _ in range(16):
            cur_res_m = cur_res_m.montgomery_mul(cur_res_m, n, n0_inv)
        cur_res_m = cur_res_m.montgomery_mul(cur_b_m, n, n0_inv)
        _ = cur_res_m.montgomery_mul(one, n, n0_inv)
    var end = perf_counter()
    print("Generic BigInt32 mod_pow (RSA-2048, e=65537):", iters / (end - start), "ops/sec")

fn main() raises:
    benchmark_generic_384()
    benchmark_generic_2048()
