from testing import assert_equal

from memory import Span

from crypto.bytes import hex_to_bytes, bytes_to_hex
from crypto.sha256 import sha256


fn test_sha256_vector() raises:
    var data = hex_to_bytes("616263")  # "abc"
    var got_arr = sha256(data)
    var got = List[UInt8]()
    for i in range(32):
        got.append(got_arr[i])
    assert_equal(
        bytes_to_hex(got),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )


fn main() raises:
    test_sha256_vector()
