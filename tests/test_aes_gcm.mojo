from testing import assert_equal

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from crypto.aes_gcm import aes_encrypt_block, aes_gcm_seal
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


fn main() raises:
    test_aes128_block_vector()
    test_gcm_vector_empty()
    test_gcm_vector_one_block()
