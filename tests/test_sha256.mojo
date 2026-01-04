from testing import assert_equal

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from crypto.sha256 import sha256_bytes
from crypto.bytes import hex_to_bytes, bytes_to_hex

fn test_sha256_empty() raises:
    var empty = hex_to_bytes("")
    var digest_empty = bytes_to_hex(sha256_bytes(empty))
    assert_equal(digest_empty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

fn test_sha256_abc() raises:
    var abc = hex_to_bytes("616263")
    var digest_abc = bytes_to_hex(sha256_bytes(abc))
    assert_equal(digest_abc, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


fn main() raises:
    test_sha256_empty()
    test_sha256_abc()
