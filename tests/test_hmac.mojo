from testing import assert_equal

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from crypto.hmac import hmac_sha256
from crypto.bytes import hex_to_bytes, bytes_to_hex

fn test_hmac_sha256_rfc4231_case1() raises:
    var key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    var data = hex_to_bytes("4869205468657265")
    var mac = hmac_sha256(key, data)
    var mac_hex = bytes_to_hex(mac)
    assert_equal(mac_hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

fn main() raises:
    test_hmac_sha256_rfc4231_case1()
