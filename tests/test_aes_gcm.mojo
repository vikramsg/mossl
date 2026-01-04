from testing import assert_equal

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from crypto.aes_gcm import aes_encrypt_block, aes_gcm_seal, aes_gcm_open
from crypto.bytes import hex_to_bytes, bytes_to_hex


fn test_aes128_block_vector() raises:
    var key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    var pt = hex_to_bytes("00112233445566778899aabbccddeeff")
    var ct = aes_encrypt_block(key, pt)
    assert_equal(bytes_to_hex(ct), "69c4e0d86a7b0430d8cdb78070b4c55a")


fn test_gcm_vector_empty() raises:
    var key = hex_to_bytes("00000000000000000000000000000000")
    var iv = hex_to_bytes("000000000000000000000000")
    var aad = hex_to_bytes("")
    var pt = hex_to_bytes("")
    var sealed = aes_gcm_seal(key, iv, aad, pt)
    var ct = sealed[0].copy()
    var tag = sealed[1].copy()
    assert_equal(bytes_to_hex(ct), "")
    assert_equal(bytes_to_hex(tag), "58e2fccefa7e3061367f1d57a4e7455a")
    var opened = aes_gcm_open(key, iv, aad, ct, tag)
    assert_equal(opened[1], True)
    assert_equal(bytes_to_hex(opened[0]), "")


fn test_gcm_vector_one_block() raises:
    var key = hex_to_bytes("00000000000000000000000000000000")
    var iv = hex_to_bytes("000000000000000000000000")
    var aad = hex_to_bytes("")
    var pt = hex_to_bytes("00000000000000000000000000000000")
    var sealed = aes_gcm_seal(key, iv, aad, pt)
    var ct = sealed[0].copy()
    var tag = sealed[1].copy()
    assert_equal(bytes_to_hex(ct), "0388dace60b6a392f328c2b971b2fe78")
    assert_equal(bytes_to_hex(tag), "ab6e47d42cec13bdf53a67b21257bddf")
    var opened = aes_gcm_open(key, iv, aad, ct, tag)
    assert_equal(opened[1], True)
    assert_equal(bytes_to_hex(opened[0]), "00000000000000000000000000000000")


fn test_gcm_vector_with_aad() raises:
    var key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
    var iv = hex_to_bytes("cafebabefacedbaddecaf888")
    var aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    var pt = hex_to_bytes(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39"
    )
    var sealed = aes_gcm_seal(key, iv, aad, pt)
    var ct = sealed[0].copy()
    var tag = sealed[1].copy()
    assert_equal(
        bytes_to_hex(ct),
        (
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091"
        ),
    )
    assert_equal(bytes_to_hex(tag), "5bc94fbc3221a5db94fae95ae7121a47")
    var opened = aes_gcm_open(key, iv, aad, ct, tag)
    assert_equal(opened[1], True)
    assert_equal(bytes_to_hex(opened[0]), bytes_to_hex(pt))


fn main() raises:
    test_aes128_block_vector()
    test_gcm_vector_empty()
    test_gcm_vector_one_block()
    test_gcm_vector_with_aad()
