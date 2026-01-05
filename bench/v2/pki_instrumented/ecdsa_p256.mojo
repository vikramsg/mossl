from collections import List

from pki_instrumented.asn1 import DerReader, read_sequence_reader, read_integer_bytes
from pki_instrumented.ec_arithmetic import UIntLimbs, verify_generic, FieldContext

from crypto_instrumented.sha256 import sha256_bytes

alias U256 = UIntLimbs[4]


fn u256_from_limbs(l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64) -> U256:
    var res = U256()
    res.limbs[0] = l0
    res.limbs[1] = l1
    res.limbs[2] = l2
    res.limbs[3] = l3
    return res


fn verify_ecdsa_p256_hash(
    pubkey: List[UInt8], hash: List[UInt8], sig_der: List[UInt8]
) raises -> Bool:
    if len(pubkey) != 65 or pubkey[0] != 0x04:
        return False

    var pub_x_bytes = List[UInt8]()
    var pub_y_bytes = List[UInt8]()
    for i in range(1, 33):
        pub_x_bytes.append(pubkey[i])
    for i in range(33, 65):
        pub_y_bytes.append(pubkey[i])

    var pub_x = U256.from_bytes(pub_x_bytes)
    var pub_y = U256.from_bytes(pub_y_bytes)

    # Hash should be truncated to 32 bytes if longer (SHA256 is 32, but general case)
    var digest = hash.copy()
    if len(digest) > 32:
        var truncated = List[UInt8]()
        for i in range(32):
            truncated.append(digest[i])
        digest = truncated^

    var hash_val = U256.from_bytes(digest)

    var reader = DerReader(sig_der)
    var seq = read_sequence_reader(reader)
    var r_bytes = read_integer_bytes(seq)
    var s_bytes = read_integer_bytes(seq)

    var r_val = U256.from_bytes(r_bytes)
    var s_val = U256.from_bytes(s_bytes)

    # Initialize Contexts (P-256)

    # P
    var p_m = u256_from_limbs(
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    )

    var p_n0_inv = UInt64(1)

    var p_r2 = u256_from_limbs(
        0x0000000000000003,
        0xFFFFFFFBFFFFFFFF,
        0xFFFFFFFFFFFFFFFE,
        0x00000004FFFFFFFD,
    )

    # 1 * R mod P
    var one = u256_from_limbs(
        0x0000000000000001,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFE,
    )

    var ctx = FieldContext[4](p_m, p_n0_inv, p_r2, one)

    # n
    var n_m = u256_from_limbs(
        0xF3B9CAC2FC632551,
        0xBCE6FAADA7179E84,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000,
    )

    var n_n0_inv = UInt64(0xCCD1C8AAEE00BC4F)

    var n_r2 = u256_from_limbs(
        0x83244C95BE79EEA2,
        0x4699799C49BD6FA6,
        0x2845B2392B6BEC59,
        0x66E12D94F3D95620,
    )

    # 1 * R mod n
    var n_one = u256_from_limbs(
        0x0C46353D039CDAAF,
        0x4319055258E8617B,
        0x0000000000000000,
        0x00000000FFFFFFFF,
    )

    var scalar_ctx = FieldContext[4](n_m, n_n0_inv, n_r2, n_one)

    # G
    var gx = u256_from_limbs(
        0xF4A13945D898C296,
        0x77037D812DEB33A0,
        0xF8BCE6E563A440F2,
        0x6B17D1F2E12C4247,
    )
    var gy = u256_from_limbs(
        0xCBB6406837BF51F5,
        0x2BCE33576B315ECE,
        0x8EE7EB4A7C0F9E16,
        0x4FE342E2FE1A7F9B,
    )

    return verify_generic(
        pub_x, pub_y, hash_val, r_val, s_val, gx, gy, ctx, scalar_ctx
    )


fn verify_ecdsa_p256(
    pubkey: List[UInt8], msg: List[UInt8], sig_der: List[UInt8]
) raises -> Bool:
    return verify_ecdsa_p256_hash(pubkey, sha256_bytes(msg), sig_der)
