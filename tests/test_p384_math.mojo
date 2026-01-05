from testing import assert_equal
from collections import List
from crypto.bytes import hex_to_bytes, bytes_to_hex
from pki.ecdsa_p384 import ECPoint384, scalar_mul, p384_gx, p384_gy, p384_p, p384_n, point_double
from pki.bigint import BigInt

fn test_p384_generator() raises:
    print("Testing P-384 Generator point...")
    var g = ECPoint384(p384_gx(), p384_gy(), False)
    
    # 1 * G = G
    var one = List[UInt64]()
    one.append(1)
    var p1 = scalar_mul(one, g)
    assert_equal(bytes_to_hex(BigInt(p1.x).to_be_bytes(48)), bytes_to_hex(BigInt(p384_gx()).to_be_bytes(48)))
    assert_equal(bytes_to_hex(BigInt(p1.y).to_be_bytes(48)), bytes_to_hex(BigInt(p384_gy()).to_be_bytes(48)))
    print("  1*G SUCCESS")

fn test_p384_double_g() raises:
    print("Testing P-384 2*G...")
    var g = ECPoint384(p384_gx(), p384_gy(), False)
    var two = List[UInt64]()
    two.append(2)
    var p2 = scalar_mul(two, g)
    
    # Expected 2*G for P-384
    # x = bd99ad396602336603a11b7d3077717462c14041e17d74542d2a452140e6c52a0887372d80c3e98150499e03d3667554
    var expected_x = "bd99ad396602336603a11b7d3077717462c14041e17d74542d2a452140e6c52a0887372d80c3e98150499e03d3667554"
    assert_equal(bytes_to_hex(BigInt(p2.x).to_be_bytes(48)), expected_x)
    print("  2*G SUCCESS")

fn test_p384_affine_double() raises:
    print("Testing P-384 affine 2*G...")
    var gx_limbs = p384_gx()
    print("  GX limbs count: " + String(len(gx_limbs)))
    for i in range(len(gx_limbs)):
        print("    limb[" + String(i) + "]: " + hex(Int(gx_limbs[i])))
        
    var g = ECPoint384(gx_limbs, p384_gy(), False)
    var p2 = point_double(g)
    
    var expected_x = "bd99ad396602336603a11b7d3077717462c14041e17d74542d2a452140e6c52a0887372d80c3e98150499e03d3667554"
    assert_equal(bytes_to_hex(BigInt(p2.x).to_be_bytes(48)), expected_x)
    print("  Affine 2*G SUCCESS")

fn main() raises:
    test_p384_generator()
    test_p384_affine_double()
    test_p384_double_g()
