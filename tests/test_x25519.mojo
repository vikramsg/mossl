from testing import assert_equal

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from crypto.x25519 import x25519
from crypto.bytes import hex_to_bytes, bytes_to_hex


fn test_x25519_rfc7748_vector1() raises:
    var scalar = hex_to_bytes(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    )
    var u = hex_to_bytes(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
    )
    var out = x25519(scalar, u)
    assert_equal(
        bytes_to_hex(out),
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    )


fn test_x25519_rfc7748_vector2() raises:
    var scalar = hex_to_bytes(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
    )
    var u = hex_to_bytes(
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
    )
    var out = x25519(scalar, u)
    assert_equal(
        bytes_to_hex(out),
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    )


fn main() raises:
    test_x25519_rfc7748_vector1()
    test_x25519_rfc7748_vector2()
