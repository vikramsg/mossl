from testing import assert_equal

from memory import Span

from crypto.bytes import hex_to_bytes, bytes_to_hex
from crypto.hmac import hmac_sha256


fn test_hmac_sha256_vector() raises:
    var key = hex_to_bytes("6b6579")  # "key"
    var data = hex_to_bytes(
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67"
    )
    var got_arr = hmac_sha256(key, data)
    var got = List[UInt8]()
    for i in range(32):
        got.append(got_arr[i])
    assert_equal(
        bytes_to_hex(got),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
    )


fn main() raises:
    test_hmac_sha256_vector()
