from collections import List
from testing import assert_false, assert_true, assert_equal

from crypto.aes_gcm import aes_gcm_open, aes_gcm_seal


fn test_aes_gcm_negative() raises:
    print("Testing AES-GCM negative validation...")
    var key = List[UInt8]()
    for _ in range(16):
        key.append(1)
    var iv = List[UInt8]()
    for _ in range(12):
        iv.append(2)
    var aad = List[UInt8]()
    var pt = List[UInt8](1, 2, 3, 4)

    var sealed = aes_gcm_seal(key, iv, aad, pt)
    var ct = sealed.ciphertext.copy()
    var tag = sealed.tag.copy()

    # 1. Corrupt tag
    var bad_tag = tag.copy()
    bad_tag[0] ^= 1
    var res = aes_gcm_open(key, iv, aad, ct, bad_tag)
    assert_false(res.success, "Opened with corrupted tag")

    # 2. Corrupt ciphertext
    var bad_ct = ct.copy()
    bad_ct[0] ^= 1
    res = aes_gcm_open(key, iv, aad, bad_ct, tag)
    assert_false(res.success, "Opened with corrupted ciphertext")

    # 3. Wrong IV
    var bad_iv = iv.copy()
    bad_iv[0] ^= 1
    res = aes_gcm_open(key, bad_iv, aad, ct, tag)
    assert_false(res.success, "Opened with wrong IV")

    # 4. Wrong AAD
    var bad_aad = List[UInt8](9, 9, 9)
    res = aes_gcm_open(key, iv, bad_aad, ct, tag)
    assert_false(res.success, "Opened with wrong AAD")

    print("AES-GCM negative tests passed!")


fn main() raises:
    test_aes_gcm_negative()
