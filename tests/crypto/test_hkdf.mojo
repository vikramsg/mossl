from testing import assert_equal

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from crypto.hkdf import hkdf_extract, hkdf_expand
from crypto.bytes import hex_to_bytes, bytes_to_hex
from memory import Span
from collections import InlineArray


fn test_hkdf_rfc5869_case1() raises:
    var ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    var salt = hex_to_bytes("000102030405060708090a0b0c")
    var info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9")

    var prk_arr = hkdf_extract(Span(salt), Span(ikm))
    var prk = List[UInt8]()
    for i in range(32):
        prk.append(prk_arr[i])
    var prk_hex = bytes_to_hex(prk)
    assert_equal(
        prk_hex,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    )

    var okm = hkdf_expand(Span(prk), Span(info), 42)
    var okm_hex = bytes_to_hex(okm)
    assert_equal(
        okm_hex,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )


fn main() raises:
    test_hkdf_rfc5869_case1()
