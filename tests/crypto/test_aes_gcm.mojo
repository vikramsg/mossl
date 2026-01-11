from testing import assert_equal, assert_true, assert_false

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from crypto.aes_gcm import (
    AESContextInline,
    Block16,
    aes_gcm_seal_internal,
    aes_gcm_open_internal,
)
from crypto.bytes import hex_to_bytes, bytes_to_hex
from memory import Span


fn test_aes128_block_vector() raises:
    var key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    var pt = hex_to_bytes("00112233445566778899aabbccddeeff")
    var key_arr = InlineArray[UInt8, 16](0)
    for i in range(16):
        key_arr[i] = key[i]
    var ctx = AESContextInline(key_arr)
    var pt_vec = Block16(0)
    for i in range(16):
        pt_vec[i] = pt[i]
    var ct_vec = ctx.encrypt_block(pt_vec)
    var ct = List[UInt8]()
    for i in range(16):
        ct.append(ct_vec[i])
    assert_equal(bytes_to_hex(ct), "69c4e0d86a7b0430d8cdb78070b4c55a")


fn test_gcm_vector_empty() raises:
    var key = hex_to_bytes("00000000000000000000000000000000")
    var iv = hex_to_bytes("000000000000000000000000")
    var aad = hex_to_bytes("")
    var pt = hex_to_bytes("")
    # 1. Mojo Seal
    var sealed = aes_gcm_seal_internal(Span(key), Span(iv), Span(aad), Span(pt))
    var ct = sealed.ciphertext.copy()
    var tag = sealed.tag

    # 2. Mojo Open
    var opened = aes_gcm_open_internal(
        Span(key), Span(iv), Span(aad), Span(ct), tag
    )
    assert_true(opened.success)
    assert_equal(len(opened.plaintext), len(pt))


fn test_gcm_vector_one_block() raises:
    var key = hex_to_bytes("00000000000000000000000000000000")
    var iv = hex_to_bytes("000000000000000000000000")
    var aad = hex_to_bytes("")
    var pt = hex_to_bytes("00000000000000000000000000000000")
    var sealed = aes_gcm_seal_internal(Span(key), Span(iv), Span(aad), Span(pt))
    var ct = sealed.ciphertext.copy()
    var tag = sealed.tag
    assert_equal(bytes_to_hex(ct), "0388dace60b6a392f328c2b971b2fe78")
    var tag_list = List[UInt8]()
    for i in range(16):
        tag_list.append(tag[i])
    assert_equal(bytes_to_hex(tag_list), "ab6e47d42cec13bdf53a67b21257bddf")
    var opened = aes_gcm_open_internal(
        Span(key), Span(iv), Span(aad), Span(ct), tag
    )
    assert_true(opened.success)
    assert_equal(
        bytes_to_hex(opened.plaintext), "00000000000000000000000000000000"
    )


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
    var sealed = aes_gcm_seal_internal(Span(key), Span(iv), Span(aad), Span(pt))
    var ct = sealed.ciphertext.copy()
    var tag = sealed.tag
    assert_equal(
        bytes_to_hex(ct),
        (
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091"
        ),
    )
    var tag_list = List[UInt8]()
    for i in range(16):
        tag_list.append(tag[i])
    assert_equal(bytes_to_hex(tag_list), "5bc94fbc3221a5db94fae95ae7121a47")
    var opened = aes_gcm_open_internal(
        Span(key), Span(iv), Span(aad), Span(ct), tag
    )
    assert_true(opened.success)
    assert_equal(bytes_to_hex(opened.plaintext), bytes_to_hex(pt))


fn main() raises:
    test_aes128_block_vector()
    test_gcm_vector_empty()
    test_gcm_vector_one_block()
    test_gcm_vector_with_aad()
