from collections import List
from testing import assert_equal

from crypto.bytes import bytes_to_hex, hex_to_bytes

from pki.bigint import (
    BigInt,
    mod_pow,
    add_mod,
    add_limbs,
    sub_limbs,
    mul_limbs,
    mod_inv,
    mod_mul,
)


fn test_large_math() raises:
    print("Testing multi-limb math...")
    # (2^64 - 1) + 1 = 2^64
    var a = List[UInt64]()
    a.append(0xFFFFFFFFFFFFFFFF)
    var b = List[UInt64]()
    b.append(1)
    var res = add_limbs(a, b)
    assert_equal(len(res), 2)
    assert_equal(res[0], 0)
    assert_equal(res[1], 1)

    # 2^64 - 1 = 2^64 - 1
    var c = List[UInt64]()
    c.append(0)
    c.append(1)
    var d = List[UInt64]()
    d.append(1)
    res = sub_limbs(c, d)
    assert_equal(len(res), 1)
    assert_equal(res[0], 0xFFFFFFFFFFFFFFFF)

    # (2^64) * (2^64) = 2^128
    var e = List[UInt64]()
    e.append(0)
    e.append(1)
    res = mul_limbs(e, e)
    assert_equal(len(res), 3)
    assert_equal(res[0], 0)
    assert_equal(res[1], 0)
    assert_equal(res[2], 1)
    print("multi-limb math tests passed!")


fn test_384bit_add_sub() raises:
    print("Testing 384-bit add/sub...")
    var p_hex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"
    var p = BigInt.from_be_bytes(hex_to_bytes(p_hex))

    var one = List[UInt64]()
    one.append(1)
    var p_plus_1 = add_limbs(p.limbs, one)
    assert_equal(len(p_plus_1), 6)

    var p_back = sub_limbs(p_plus_1, one)
    assert_equal(bytes_to_hex(BigInt(p_back).to_be_bytes(48)), p_hex)
    print("384-bit add/sub tests passed!")


fn test_mod_pow_basic() raises:
    # 3^4 mod 10 = 81 mod 10 = 1
    var base = BigInt(List[UInt8](3)).limbs.copy()
    var exp = BigInt(List[UInt8](4)).limbs.copy()
    var mod = BigInt(List[UInt8](10)).limbs.copy()
    var res = mod_pow(base, exp, mod)
    assert_equal(len(res), 1)
    assert_equal(res[0], 1)


fn test_mod_pow_large() raises:
    var base = BigInt(List[UInt8](7)).limbs.copy()
    var exp = BigInt(List[UInt8](13)).limbs.copy()
    var mod = BigInt(List[UInt8](11)).limbs.copy()
    var res = mod_pow(base, exp, mod)
    assert_equal(len(res), 1)
    assert_equal(res[0], 2)


fn test_add_mod() raises:
    # 1 + 1 mod 3 = 2
    var a = BigInt(List[UInt8](1)).limbs.copy()
    var b = BigInt(List[UInt8](1)).limbs.copy()
    var mod = BigInt(List[UInt8](3)).limbs.copy()
    var res = add_mod(a, b, mod)
    assert_equal(len(res), 1)
    assert_equal(res[0], 2)
    print("add_mod tests passed!")


fn test_to_be_bytes() raises:
    print("Testing to_be_bytes...")
    var limbs = List[UInt64]()
    limbs.append(0x1122334455667788)
    var b = BigInt(limbs)
    var bytes = b.to_be_bytes(8)
    assert_equal(bytes_to_hex(bytes), "1122334455667788")
    print("to_be_bytes tests passed!")


fn test_mod_inv() raises:
    print("Testing mod_inv...")
    # 2^-1 mod 5 = 3
    var a = BigInt(List[UInt8](2)).limbs.copy()
    var mod = BigInt(List[UInt8](5)).limbs.copy()
    var res = mod_inv(a, mod)
    assert_equal(len(res), 1)
    assert_equal(res[0], 3)
    print("mod_inv tests passed!")


fn test_large_mod_inv() raises:
    print("Testing large mod_inv...")

    var p = BigInt.from_be_bytes(
        hex_to_bytes(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"
        )
    )

    var den = BigInt.from_be_bytes(
        hex_to_bytes(
            "6c2fbc952c4c58debb3d317f2525b853f1e83b7a513428f9d3b462276be1718014c1639c3afd033af4863af921d41cbe"
        )
    )

    # Expected den^-1 mod p

    var expected_den_inv = "cf774118d2c89e45562d4781dc97f749fb682d2bbbe585fc3831c84f3f2b417b51339b593018f2003767804fafce4118"

    var den_inv = mod_inv(den.limbs, p.limbs)

    assert_equal(
        bytes_to_hex(BigInt(den_inv).to_be_bytes(48)), expected_den_inv
    )

    print("large mod_inv test passed!")


fn test_large_mod_mul() raises:
    print("Testing large mod_mul...")

    var p_hex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"

    var den_hex = "6c2fbc952c4c58debb3d317f2525b853f1e83b7a513428f9d3b462276be1718014c1639c3afd033af4863af921d41cbe"

    var expected_hex = "768fe134db3c9bc78761959f4a200b4ef09f6780776502e709c06b38ff246fdf237fe4cf234bb99149b477659035583b"

    var p = BigInt.from_be_bytes(hex_to_bytes(p_hex))

    var den = BigInt.from_be_bytes(hex_to_bytes(den_hex))

    var res = mod_mul(den.limbs, den.limbs, p.limbs)

    assert_equal(bytes_to_hex(BigInt(res).to_be_bytes(48)), expected_hex)

    print("large mod_mul test passed!")


from pki.bigint import (
    BigInt,
    mod_pow,
    add_mod,
    add_limbs,
    sub_limbs,
    mul_limbs,
    mod_inv,
    mod_mul,
    mod_reduce,
    shift_left,
)


fn test_shift_left() raises:
    print("Testing shift_left...")

    var a = List[UInt64]()
    a.append(1)

    var res = shift_left(a, 1)

    assert_equal(len(res), 1)

    assert_equal(res[0], 2)

    res = shift_left(a, 64)

    assert_equal(len(res), 2)

    assert_equal(res[0], 0)

    assert_equal(res[1], 1)

    print("shift_left tests passed!")


fn test_mod_reduce() raises:
    print("Testing mod_reduce...")

    # 10 mod 3 = 1

    var n = List[UInt64]()
    n.append(10)

    var m = List[UInt64]()
    m.append(3)

    var res = mod_reduce(n^, m.copy())

    assert_equal(len(res), 1)

    assert_equal(res[0], 1)

    # Large n, small m

    # 2^64 mod 3 = 1 (since 2^64 = (3-1)^64 = (-1)^64 = 1 mod 3)

    n = List[UInt64]()
    n.append(0)
    n.append(1)

    res = mod_reduce(n^, m.copy())

    assert_equal(len(res), 1)

    assert_equal(res[0], 1)

    print("mod_reduce tests passed!")


fn test_bit_length() raises:
    print("Testing bit_length...")

    var a = List[UInt64]()
    a.append(1)

    assert_equal(BigInt(a).bit_length(), 1)

    a.clear()

    a.append(0)
    a.append(1)

    assert_equal(BigInt(a).bit_length(), 65)

    a.clear()

    a.append(0xFFFFFFFFFFFFFFFF)

    assert_equal(BigInt(a).bit_length(), 64)

    print("bit_length tests passed!")


fn main() raises:
    test_bit_length()

    test_large_math()

    test_shift_left()

    test_mod_reduce()

    test_large_mod_mul()

    test_384bit_add_sub()

    test_mod_pow_basic()

    test_mod_pow_large()

    test_add_mod()

    test_to_be_bytes()

    test_mod_inv()

    test_large_mod_inv()

    print("BigInt tests passed!")
