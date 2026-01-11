from testing import assert_equal

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from tls.record_layer import RecordSealer, build_nonce
from crypto.bytes import hex_to_bytes, bytes_to_hex


fn test_nonce_derivation_seq0_seq1() raises:
    var iv = hex_to_bytes("000000000000000000000000")
    var nonce0 = build_nonce(iv, UInt64(0))
    var nonce1 = build_nonce(iv, UInt64(1))
    assert_equal(bytes_to_hex(nonce0), "000000000000000000000000")
    assert_equal(bytes_to_hex(nonce1), "000000000000000000000001")


fn test_sealer_sequence_progression() raises:
    var key = hex_to_bytes("00000000000000000000000000000000")
    var iv = hex_to_bytes("000000000000000000000000")
    var sealer = RecordSealer(key, iv)
    var sealed0 = sealer.seal(hex_to_bytes(""), hex_to_bytes(""))
    var sealed1 = sealer.seal(hex_to_bytes(""), hex_to_bytes(""))
    var nonce0 = sealed0.nonce.copy()
    var nonce1 = sealed1.nonce.copy()
    assert_equal(bytes_to_hex(nonce0), "000000000000000000000000")
    assert_equal(bytes_to_hex(nonce1), "000000000000000000000001")


fn main() raises:
    test_nonce_derivation_seq0_seq1()
    test_sealer_sequence_progression()
