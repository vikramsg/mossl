from collections import List
from bit import count_leading_zeros

struct BigInt(Movable):
    var limbs: List[UInt64]

    fn __init__(out self, limbs: List[UInt64]):
        self.limbs = limbs.copy()

    fn __init__(out self, bytes: List[UInt8]):
        self.limbs = List[UInt64]()
        var i = len(bytes)
        while i > 0:
            var v = UInt64(0)
            var count = 0
            while i > 0 and count < 8:
                v |= UInt64(bytes[i-1]) << (count * 8)
                i -= 1
                count += 1
            self.limbs.append(v)
        self.trim()

    fn trim(mut self):
        while len(self.limbs) > 0 and self.limbs[len(self.limbs)-1] == 0:
            _ = self.limbs.pop()

    @staticmethod
    fn from_be_bytes(bytes: List[UInt8]) -> BigInt:
        var res = List[UInt64]()
        var i = len(bytes)
        while i > 0:
            var v = UInt64(0)
            var count = 0
            while i > 0 and count < 8:
                v |= UInt64(bytes[i-1]) << (count * 8)
                i -= 1
                count += 1
            res.append(v)
        var b = BigInt(res)
        b.trim()
        return b^

    fn is_zero(self) -> Bool:
        return len(self.limbs) == 0

    fn bit_length(self) -> Int:
        if self.is_zero(): return 0
        var i = len(self.limbs) - 1
        var v = self.limbs[i]
        # Use Mojo's native count_leading_zeros
        return (i + 1) * 64 - Int(count_leading_zeros(v))

    fn to_be_bytes(self, target_len: Int = 0) -> List[UInt8]:
        var res = List[UInt8]()
        for i in range(len(self.limbs)):
            var v = self.limbs[i]
            for _ in range(8):
                res.append(UInt8(v & 0xFF))
                v >>= 8
        while len(res) > 0 and res[len(res)-1] == 0: _ = res.pop()
        var actual_len = len(res)
        var length = target_len if target_len > actual_len else actual_len
        if length == 0: length = 1
        var out = List[UInt8]()
        for i in range(length):
            var idx = length - 1 - i
            if idx < actual_len: out.append(res[idx])
            else: out.append(0)
        return out.copy()

fn cmp_limbs(a: List[UInt64], b: List[UInt64]) -> Int:
    var i_max = len(a) - 1
    var j_max = len(b) - 1
    while i_max >= 0 and a[i_max] == 0: i_max -= 1
    while j_max >= 0 and b[j_max] == 0: j_max -= 1
    if i_max > j_max: return 1
    if i_max < j_max: return -1
    var i = i_max
    while i >= 0:
        if a[i] > b[i]: return 1
        if a[i] < b[i]: return -1
        i -= 1
    return 0

fn add_limbs(a: List[UInt64], b: List[UInt64]) -> List[UInt64]:
    var out = List[UInt64]()
    var carry = UInt128(0)
    var i = 0
    var len_a = len(a)
    var len_b = len(b)
    var max_len = len_a if len_a > len_b else len_b
    while i < max_len:
        var sum = carry
        if i < len_a: sum += UInt128(a[i])
        if i < len_b: sum += UInt128(b[i])
        out.append(UInt64(sum & 0xFFFFFFFFFFFFFFFF))
        carry = sum >> 64
        i += 1
    if carry > 0:
        out.append(UInt64(carry))
    return out.copy()

fn sub_limbs(a: List[UInt64], b: List[UInt64]) -> List[UInt64]:
    var out = List[UInt64]()
    var borrow = Int128(0)
    for i in range(len(a)):
        var ai = Int128(a[i])
        var bi = Int128(0)
        if i < len(b): bi = Int128(b[i])
        var diff = ai - bi - borrow
        if diff < 0:
            out.append(UInt64((diff + (Int128(1) << 64)) & 0xFFFFFFFFFFFFFFFF))
            borrow = 1
        else:
            out.append(UInt64(diff & 0xFFFFFFFFFFFFFFFF))
            borrow = 0
    while len(out) > 0 and out[len(out)-1] == 0: _ = out.pop()
    return out.copy()

fn mul_limbs(a: List[UInt64], b: List[UInt64]) -> List[UInt64]:
    if len(a) == 0 or len(b) == 0: return List[UInt64]()
    var out = List[UInt64]()
    for _ in range(len(a) + len(b)): out.append(0)
    for i in range(len(a)):
        var carry = UInt128(0)
        var ai = UInt128(a[i])
        for j in range(len(b)):
            var prod = ai * UInt128(b[j]) + UInt128(out[i+j]) + carry
            out[i+j] = UInt64(prod & 0xFFFFFFFFFFFFFFFF)
            carry = prod >> 64
        out[i+len(b)] = UInt64(carry)
    while len(out) > 0 and out[len(out)-1] == 0: _ = out.pop()
    return out.copy()

fn shift_left(a: List[UInt64], n: Int) -> List[UInt64]:
    if n == 0: return a.copy()
    var word_shift = n // 64
    var bit_shift = n % 64
    var out = List[UInt64]()
    for _ in range(word_shift): out.append(0)
    var carry = UInt64(0)
    if bit_shift == 0:
        for i in range(len(a)): out.append(a[i])
    else:
        for i in range(len(a)):
            var v = a[i]
            out.append((v << bit_shift) | carry)
            carry = v >> (64 - bit_shift)
        if carry > 0: out.append(carry)
    return out.copy()

fn mod_reduce(var n: List[UInt64], m: List[UInt64]) -> List[UInt64]:
    if len(m) == 0: return List[UInt64]()
    if cmp_limbs(n, m) < 0: return n.copy()
    
    var m_bi = BigInt(m)
    var m_bits = m_bi.bit_length()
    
    while True:
        var n_bi = BigInt(n)
        var n_bits = n_bi.bit_length()
        var shift = n_bits - m_bits
        if shift < 0: break
        
        var m_s = shift_left(m, shift)
        if cmp_limbs(n, m_s) < 0:
            if shift == 0: break
            m_s = shift_left(m, shift - 1)
            
        n = sub_limbs(n, m_s)
    return n.copy()

fn mod_pow(base: List[UInt64], exp: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    if len(mod) == 0: return List[UInt64]()
    var res = List[UInt64](); res.append(1)
    var b = mod_reduce(base.copy(), mod)
    var e_bi = BigInt(exp)
    var bits = e_bi.bit_length()
    
    for i in range(bits):
        var bit_idx = bits - 1 - i
        var limb_idx = bit_idx // 64
        var bit_in_limb = bit_idx % 64
        
        res = mod_mul(res, res, mod)
        if ((exp[limb_idx] >> bit_in_limb) & 1) == 1:
            res = mod_mul(res, b, mod)
            
    return res.copy()

fn add_mod(a: List[UInt64], b: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    var sum = add_limbs(a, b)
    if cmp_limbs(sum, mod) >= 0: return sub_limbs(sum, mod)
    return sum.copy()

fn sub_mod(a: List[UInt64], b: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    if cmp_limbs(a, b) >= 0: return sub_limbs(a, b)
    return sub_limbs(add_limbs(a, mod), b)

fn mod_mul(a: List[UInt64], b: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    return mod_reduce(mul_limbs(a, b), mod)

fn mod_inv(a: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    var two = List[UInt64](); two.append(2)
    var exp = sub_limbs(mod.copy(), two)
    return mod_pow(a, exp, mod)