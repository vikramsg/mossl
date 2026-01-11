from collections import List

from logger import Level, Logger
from memory import Span
from python import Python

from crypto.aes_gcm import aes_gcm_seal_internal, aes_gcm_open_internal

from tests.crypto.diff_utils import (
    to_python_bytes,
    from_python_bytes,
    assert_equal_bytes,
)

fn test_aes_gcm_diff() raises:
    var log = Logger[Level.INFO]()
    log.info("Testing AES-GCM differential with 1000 iterations...")
    var aead = Python.import_module(
        "cryptography.hazmat.primitives.ciphers.aead"
    )
    var os = Python.import_module("os")
    var random = Python.import_module("random")

    for i in range(1000):
        # AES-128 GCM
        var key_py = os.urandom(16)
        var iv_py = os.urandom(12)

        var pt_len = Int(random.randint(0, 500))
        var pt_py = os.urandom(pt_len)

        var aad_len = Int(random.randint(0, 100))
        var aad_py = os.urandom(aad_len)

        # Convert to Mojo
        var key = List[UInt8]()
        for j in range(16):
            key.append(UInt8(Int(key_py[j])))
        var iv = List[UInt8]()
        for j in range(12):
            iv.append(UInt8(Int(iv_py[j])))
        var pt = List[UInt8]()
        for j in range(pt_len):
            pt.append(UInt8(Int(pt_py[j])))
        var aad = List[UInt8]()
        for j in range(aad_len):
            aad.append(UInt8(Int(aad_py[j])))

        # 1. Mojo Seal
        var sealed = aes_gcm_seal_internal(
            Span(key), Span(iv), Span(aad), Span(pt)
        )
        var ct = sealed.ciphertext.copy()
        var tag = sealed.tag

        # 2. Python Seal
        var aes_py = aead.AESGCM(key_py)
        var ct_tag_py = aes_py.encrypt(iv_py, pt_py, aad_py)

        # Python returns CT + Tag concatenated
        var py_ct = ct_tag_py[:pt_len]
        var py_tag = ct_tag_py[pt_len:]

        assert_equal_bytes(
            ct, py_ct, "AES-GCM CT mismatch at iteration " + String(i)
        )
        var tag_list = List[UInt8]()
        for j in range(16):
            tag_list.append(tag[j])
        assert_equal_bytes(
            tag_list, py_tag, "AES-GCM Tag mismatch at iteration " + String(i)
        )

        # 3. Mojo Open (Round-trip)
        var opened = aes_gcm_open_internal(
            Span(key), Span(iv), Span(aad), Span(ct), tag
        )
        if not opened.success:
            raise Error("AES-GCM Mojo open failed at iteration " + String(i))

        # Compare opened PT with original PT
        for j in range(pt_len):
            if opened.plaintext[j] != pt[j]:
                raise Error(
                    "AES-GCM PT mismatch after Mojo open at iteration "
                    + String(i)
                )

        # 4. Python Open (Cross round-trip)
        var py_opened = aes_py.decrypt(iv_py, ct_tag_py, aad_py)
        assert_equal_bytes(
            pt,
            py_opened,
            "AES-GCM PT mismatch after Python open at iteration " + String(i),
        )

        if i % 100 == 0:
            log.info("Iteration", i, "passed")

    log.info("AES-GCM differential test passed!")


fn main() raises:
    test_aes_gcm_diff()
