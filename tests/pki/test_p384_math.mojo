from collections import List
from testing import assert_equal

from pki.bigint import BigInt

from crypto.bytes import hex_to_bytes, bytes_to_hex

from pki.ecdsa_p384 import (
    ECPoint384,
    scalar_mul,
    p384_gx,
    p384_gy,
    p384_p,
    p384_n,
    point_double,
)


fn test_p384_generator() raises:
    var g = ECPoint384(p384_gx(), p384_gy(), False)

    # 1 * G = G
    var one = List[UInt64]()
    one.append(1)
    var p1 = scalar_mul(one, g)
    assert_equal(
        bytes_to_hex(BigInt(p1.x).to_be_bytes(48)),
        bytes_to_hex(BigInt(p384_gx()).to_be_bytes(48)),
    )
    assert_equal(
        bytes_to_hex(BigInt(p1.y).to_be_bytes(48)),
        bytes_to_hex(BigInt(p384_gy()).to_be_bytes(48)),
    )


fn test_p384_double_g() raises:
    var g = ECPoint384(p384_gx(), p384_gy(), False)
    var two = List[UInt64]()
    two.append(2)
    var p2 = scalar_mul(two, g)

    # Expected 2*G for P-384
    var expected_x = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61"
    var expected_y = "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80"
    assert_equal(bytes_to_hex(BigInt(p2.x).to_be_bytes(48)), expected_x)
    assert_equal(bytes_to_hex(BigInt(p2.y).to_be_bytes(48)), expected_y)


fn test_p384_affine_double() raises:
    var gx_limbs = p384_gx()

    var g = ECPoint384(gx_limbs^, p384_gy(), False)
    var p2 = point_double(g)

    var expected_x = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61"
    var expected_y = "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80"
    assert_equal(bytes_to_hex(BigInt(p2.x).to_be_bytes(48)), expected_x)
    assert_equal(bytes_to_hex(BigInt(p2.y).to_be_bytes(48)), expected_y)


fn main() raises:
    test_p384_generator()
    test_p384_affine_double()
    test_p384_double_g()
