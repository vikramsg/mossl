from testing import assert_equal
from crypto.x25519 import x25519
from crypto.bytes import hex_to_bytes, bytes_to_hex
from memory import Span

fn test_x25519_vector() raises:
    # RFC 7748 test vector
    var a_priv = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    var b_pub = hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b7f032fd43d410776d5423f")
    var expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    
    var got = x25519(a_priv, b_pub)
    assert_equal(bytes_to_hex(got), expected)

fn main() raises:
    test_x25519_vector()