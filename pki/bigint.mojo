from collections import List

struct BigInt(Movable):
    var limbs: List[UInt64]

    fn __init__(out self, limbs: List[UInt64]):
        self.limbs = limbs.copy()

    fn __init__(out self, bytes: List[UInt8]):
        self.limbs = List[UInt64]()
        # Little-endian limbs
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
        var i = len(self.limbs) - 1
        while i >= 0:
            if self.limbs[i] != UInt64(0):
                break
            _ = self.limbs.pop()
            i -= 1

    fn is_zero(self) -> Bool:
        for v in self.limbs:
            if v != 0: return False
        return True

    fn bit_length(self) -> Int:
        if self.is_zero():
            return 0
        var i = len(self.limbs) - 1
        while i >= 0 and self.limbs[i] == 0: i -= 1
        if i < 0: return 0
        var v = self.limbs[i]
        var bits = 0
        while v != UInt64(0):
            v >>= 1
            bits += 1
        return i * 64 + bits

    fn get_bit(self, idx: Int) -> Bool:
        var limb = idx // 64
        var bit = idx % 64
        if limb >= len(self.limbs):
            return False
        return ((self.limbs[limb] >> bit) & UInt64(1)) == UInt64(1)

    fn to_be_bytes(self, target_len: Int = 0) -> List[UInt8]:
        var out = List[UInt8]()
        for i in range(len(self.limbs)):
            var v = self.limbs[i]
            for _ in range(8):
                out.append(UInt8(v & 0xFF))
                v >>= 8
        
        var final = List[UInt8]()
        var length = target_len if target_len > 0 else (len(out) if len(out) > 0 else 1)
        
        for i in range(length):
            if i < len(out):
                final.append(out[len(out)-1-i])
            else:
                final.append(0)
        return final^

fn cmp_limbs(a: List[UInt64], b: List[UInt64]) -> Int:
    var i = len(a) - 1
    var j = len(b) - 1
    while i >= 0 and a[i] == 0: i -= 1
    while j >= 0 and b[j] == 0: j -= 1
    if i > j: return 1
    if i < j: return -1
    while i >= 0:
        if a[i] > b[i]: return 1
        if a[i] < b[i]: return -1
        i -= 1
    return 0

fn add_limbs(a: List[UInt64], b: List[UInt64]) -> List[UInt64]:
    var out = List[UInt64]()
    var carry = UInt128(0)
    var i = 0
    var max_len = len(a)
    if len(b) > max_len: max_len = len(b)
    while i < max_len or carry > 0:
        var sum = carry
        if i < len(a): sum += UInt128(a[i])
        if i < len(b): sum += UInt128(b[i])
        out.append(UInt64(sum & 0xFFFFFFFFFFFFFFFF))
        carry = sum >> 64
        i += 1
    return out^

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
    return out^

fn mul_limbs(a: List[UInt64], b: List[UInt64]) -> List[UInt64]:
    var out = List[UInt64]()
    for _ in range(len(a) + len(b)):
        out.append(0)
    for i in range(len(a)):
        var carry = UInt128(0)
        for j in range(len(b)):
            var prod = UInt128(a[i]) * UInt128(b[j]) + UInt128(out[i+j]) + carry
            out[i+j] = UInt64(prod & 0xFFFFFFFFFFFFFFFF)
            carry = prod >> 64
        out[i+len(b)] = UInt64(carry)
    return out^

fn mod_reduce(var n: List[UInt64], m: List[UInt64]) -> List[UInt64]:
    if cmp_limbs(n, m) < 0:
        return n.copy()
    
    var n_bits = 0
    var i = len(n) - 1
    while i >= 0:
        if n[i] != 0:
            var v = n[i]
            var b = 0
            while v != 0:
                v >>= 1
                b += 1
            n_bits = i * 64 + b
            break
        i -= 1
    
    var m_bits = 0
    i = len(m) - 1
    while i >= 0:
        if m[i] != 0:
            var v = m[i]
            var b = 0
            while v != 0:
                v >>= 1
                b += 1
            m_bits = i * 64 + b
            break
        i -= 1

    var shift = n_bits - m_bits
    while shift >= 0:
        var m_shifted = List[UInt64]()
        var word_shift = shift // 64
        var bit_shift = shift % 64
        for _ in range(word_shift): m_shifted.append(0)
        var carry = UInt64(0)
        if bit_shift == 0:
            for k in range(len(m)): m_shifted.append(m[k])
        else:
            for k in range(len(m)):
                var v = m[k]
                m_shifted.append((v << bit_shift) | carry)
                carry = v >> (64 - bit_shift)
            if carry > 0: m_shifted.append(carry)
        
        if cmp_limbs(n, m_shifted) >= 0:
            n = sub_limbs(n.copy(), m_shifted.copy())
        shift -= 1
    return n^

fn mod_pow(base: List[UInt64], exp: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    var res = List[UInt64]()
    res.append(1)
    var b = mod_reduce(base.copy(), mod.copy())
    
    var exp_bits = 0
    var i = len(exp) - 1
    while i >= 0:
        if exp[i] != 0:
            var v = exp[i]
            var bits = 0
            while v != 0:
                v >>= 1
                bits += 1
            exp_bits = i * 64 + bits
            break
        i -= 1

    for j in range(exp_bits):
        var limb = j // 64
        var bit = j % 64
        if ((exp[limb] >> bit) & 1) == 1:
            res = mod_reduce(mul_limbs(res.copy(), b.copy()), mod.copy())
        b = mod_reduce(mul_limbs(b.copy(), b.copy()), mod.copy())
    return res^

fn add_mod(a: List[UInt64], b: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    var sum = add_limbs(a.copy(), b.copy())
    if cmp_limbs(sum, mod) >= 0:
        return sub_limbs(sum.copy(), mod.copy()).copy()
    return sum.copy()

fn sub_mod(a: List[UInt64], b: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    if cmp_limbs(a, b) >= 0:
        return sub_limbs(a.copy(), b.copy()).copy()
    return sub_limbs(add_limbs(a.copy(), mod.copy()), b.copy()).copy()

fn mod_mul(a: List[UInt64], b: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    return mod_reduce(mul_limbs(a.copy(), b.copy()), mod.copy()).copy()

fn mod_inv(a: List[UInt64], mod: List[UInt64]) -> List[UInt64]:
    # Fermat's Little Theorem: a^(p-2) mod p
    var two = List[UInt64]()
    two.append(2)
    var exp = sub_limbs(mod.copy(), two.copy())
    return mod_pow(a.copy(), exp.copy(), mod.copy()).copy()