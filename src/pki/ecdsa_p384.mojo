from collections import List, InlineArray

from pki.asn1 import DerReader, read_sequence_reader, read_integer_bytes
from pki.ec_arithmetic import UIntLimbs, verify_generic, FieldContext

alias U384 = UIntLimbs[6]


# Helper to construct U384 from limbs (LSB first)
fn u384_from_limbs(
    l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64, l4: UInt64, l5: UInt64
) -> U384:
    var res = U384()
    res.limbs[0] = l0
    res.limbs[1] = l1
    res.limbs[2] = l2
    res.limbs[3] = l3
    res.limbs[4] = l4
    res.limbs[5] = l5
    return res


fn verify_ecdsa_p384_hash(
    pubkey: List[UInt8], hash: List[UInt8], sig_der: List[UInt8]
) raises -> Bool:
    if len(pubkey) != 97 or pubkey[0] != 0x04:
        return False

    var pub_x_bytes = List[UInt8]()
    var pub_y_bytes = List[UInt8]()
    for i in range(1, 49):
        pub_x_bytes.append(pubkey[i])
    for i in range(49, 97):
        pub_y_bytes.append(pubkey[i])

    var pub_x = U384.from_bytes(pub_x_bytes)
    var pub_y = U384.from_bytes(pub_y_bytes)

    var hash_val = U384.from_bytes(hash)

    var reader = DerReader(sig_der)
    var seq = read_sequence_reader(reader)
    var r_bytes = read_integer_bytes(seq)
    var s_bytes = read_integer_bytes(seq)

    var r_val = U384.from_bytes(r_bytes)
    var s_val = U384.from_bytes(s_bytes)

    # Initialize Contexts

    # P
    var p_m = u384_from_limbs(
        0x00000000FFFFFFFF,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    )

    var p_n0_inv = UInt64(0x100000001)

    # R^2 mod P
    var p_r2 = u384_from_limbs(
        0xFFFFFFFE00000001,
        0x0000000200000000,  # Fixed from original 0x200000000 (was 33 bits? No, 0x2 followed by 8 zeros = 33 bits? 2^33)
        # Original: 0x200000000. 2 * 16^8 = 2 * 2^32 = 2^33.
        # Fits in UInt64.
        0xFFFFFFFE00000000,
        0x0000000200000000,  # Original: 0x200000000
        0x1,
        0x0,
    )
    # Checking original hex constants:
    # 0x200000000 -> 34 bits.
    # U384(..., 0x200000000, ...). That fits in UInt64.

    var p_one = u384_from_limbs(
        0xFFFFFFFF00000001, 0xFFFFFFFF, 0x1, 0x0, 0x0, 0x0
    )

    var ctx = FieldContext[6](p_m, p_n0_inv, p_r2, p_one)

    # n
    var n_m = u384_from_limbs(
        0xECEC196ACCC52973,
        0x581A0DB248B0A77A,
        0xC7634D81F4372DDF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    )

    var n_n0_inv = UInt64(0x6ED46089E88FDC45)

    var n_r2 = u384_from_limbs(
        0x2D319B2419B409A9,
        0xFF3D81E5DF1AA419,
        0xBC3E483AFCB82947,
        0xD40D49174AAB1CC5,
        0x3FB05B7A28266895,
        0x0C84EE012B39BF21,  # 0xC84EE012B39BF21 (added leading 0 for align)
    )

    var n_one = u384_from_limbs(
        0x1313E695333AD68D,
        0xA7E5F24DB74F5885,
        0x389CB27E0BC8D220,
        0x0,
        0x0,
        0x0,
    )

    var scalar_ctx = FieldContext[6](n_m, n_n0_inv, n_r2, n_one)

    # G
    var gx = u384_from_limbs(
        0x3A545E3872760AB7,
        0x5502F25DBF55296C,
        0x59F741E082542A38,
        0x6E1D3B628BA79B98,
        0x8EB1C71EF320AD74,
        0xAA87CA22BE8B0537,
    )
    var gy = u384_from_limbs(
        0x7A431D7C90EA0E5F,
        0x0A60B1CE1D7E819D,
        0xE9DA3113B5F0B8C0,
        0xF8F41DBD289A147C,
        0x5D9E98BF9292DC29,
        0x3617DE4A96262C6F,
    )

    return verify_generic(
        pub_x, pub_y, hash_val, r_val, s_val, gx, gy, ctx, scalar_ctx
    )
