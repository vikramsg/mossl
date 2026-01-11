from collections import List
from testing import assert_true, assert_false, assert_equal

from crypto.bytes import hex_to_bytes
from crypto.sha256 import sha256_bytes

from pki.ec_arithmetic import (
    UIntLimbs,
    verify_generic,
    FieldContext,
    mont_mul,
    sub_limbs,
    cmp,
)


fn get_p256_params() -> (
    UIntLimbs[4],
    UIntLimbs[4],
    UIntLimbs[4],
    FieldContext[4],
    FieldContext[4],
):
    # P-256
    # p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    var p_m = UIntLimbs[4]()
    p_m.limbs[0] = 0xFFFFFFFFFFFFFFFF
    p_m.limbs[1] = 0x00000000FFFFFFFF
    p_m.limbs[2] = 0x0000000000000000
    p_m.limbs[3] = 0xFFFFFFFF00000001

    # n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    var n_m = UIntLimbs[4]()
    n_m.limbs[0] = 0xF3B9CAC2FC632551
    n_m.limbs[1] = 0xBCE6FAADA7179E84
    n_m.limbs[2] = 0xFFFFFFFFFFFFFFFF
    n_m.limbs[3] = 0xFFFFFFFF00000000

    # G
    # x = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    var gx = UIntLimbs[4]()
    gx.limbs[0] = 0xF4A13945D898C296
    gx.limbs[1] = 0x77037D812DEB33A0
    gx.limbs[2] = 0xF8BCE6E563A440F2
    gx.limbs[3] = 0x6B17D1F2E12C4247

    # y = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    var gy = UIntLimbs[4]()
    gy.limbs[0] = 0xCBB6406837BF51F5
    gy.limbs[1] = 0x2BCE33576B315ECE
    gy.limbs[2] = 0x8EE7EB4A7C0F9E16
    gy.limbs[3] = 0x4FE342E2FE1A7F9B

    # Constants for Montgomery (precomputed)
    # R^2 mod P
    var p_r2 = UIntLimbs[4]()
    p_r2.limbs[0] = 0x0000000000000003
    p_r2.limbs[1] = 0xFFFFFFFBFFFFFFFF
    p_r2.limbs[2] = 0xFFFFFFFFFFFFFFFE
    p_r2.limbs[3] = 0x00000004FFFFFFFD

    # n0_inv for P: 1
    var p_n0_inv = UInt64(1)

    # 1 * R mod P
    var one_mont_p = UIntLimbs[4]()
    one_mont_p.limbs[0] = 0x0000000000000001
    one_mont_p.limbs[1] = 0xFFFFFFFF00000000
    one_mont_p.limbs[2] = 0xFFFFFFFFFFFFFFFF
    one_mont_p.limbs[3] = 0x00000000FFFFFFFE

    var ctx = FieldContext[4](p_m, p_n0_inv, p_r2, one_mont_p)

    # Constants for Order n
    # R^2 mod n
    var n_r2 = UIntLimbs[4]()
    n_r2.limbs[0] = 0x83244C95BE79EEA2
    n_r2.limbs[1] = 0x4699799C49BD6FA6
    n_r2.limbs[2] = 0x2845B2392B6BEC59
    n_r2.limbs[3] = 0x66E12D94F3D95620

    # n0_inv for n: 0xccd1c8aaee00bc4f
    var n_n0_inv = UInt64(0xCCD1C8AAEE00BC4F)

    # 1 * R mod n
    var one_mont_n = UIntLimbs[4]()
    one_mont_n.limbs[0] = 0x0C46353D039CDAAF
    one_mont_n.limbs[1] = 0x4319055258E8617B
    one_mont_n.limbs[2] = 0x0000000000000000
    one_mont_n.limbs[3] = 0x00000000FFFFFFFF

    var scalar_ctx = FieldContext[4](n_m, n_n0_inv, n_r2, one_mont_n)

    var literal_one = UIntLimbs[4]()
    literal_one.limbs[0] = 1

    return (gx, gy, literal_one, ctx, scalar_ctx)


fn test_p256_arithmetic() raises:
    var params = get_p256_params()
    var ctx = params[3]
    var literal_one = params[2]

    # Test mont_mul
    # Convert 1 to Mont: 1 * R^2 * R^-1 = 1 * R
    # ctx.one is already 1 * R mod P
    var one_mont = ctx.one

    # 1 * 1 = 1
    var res_mont = mont_mul(one_mont, one_mont, ctx.m, ctx.n0_inv)
    var res = mont_mul(
        res_mont, literal_one, ctx.m, ctx.n0_inv
    )  # Convert back: res_mont * 1 * R^-1 = res

    assert_equal(res.limbs[0], 1)

    # 2 * 2 = 4
    var two = UIntLimbs[4]()
    two.limbs[0] = 2
    var two_mont = mont_mul(two, ctx.r2, ctx.m, ctx.n0_inv)
    var four_mont = mont_mul(two_mont, two_mont, ctx.m, ctx.n0_inv)
    var four = mont_mul(four_mont, literal_one, ctx.m, ctx.n0_inv)

    assert_equal(four.limbs[0], 4)


fn main() raises:
    test_p256_arithmetic()
