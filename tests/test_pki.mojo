from collections import List
from testing import assert_equal
from crypto.bytes import hex_to_bytes
from pki.x509 import parse_certificate, verify_certificate_signature, TrustStore, verify_chain, hostname_matches

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.

fn cert_bytes() -> List[UInt8]:
    var hex = "308201993082013fa0030201020214375c9be3a517f7f886e22cd40b00b9e119"
    hex += "1caef2300a06082a8648ce3d04030230163114301206035504030c0b6578616d"
    hex += "706c652e636f6d301e170d3236303130343139303235365a170d323630313035"
    hex += "3139303235365a30163114301206035504030c0b6578616d706c652e636f6d30"
    hex += "59301306072a8648ce3d020106082a8648ce3d0301070342000450811746eab7"
    hex += "c3ad1fc1274a83bbeef27aa4df07142de4cf527a65ad1c3f22db3d1b090c2bcb"
    hex += "62ef7c960257e41fc03a4fb38de921d9e1446b89db95bced5e04a36b3069301d"
    hex += "0603551d0e041604141b0c46a135d8c0f94b0189a86601c215bae5865a301f06"
    hex += "03551d230418301680141b0c46a135d8c0f94b0189a86601c215bae5865a300f"
    hex += "0603551d130101ff040530030101ff30160603551d11040f300d820b6578616d"
    hex += "706c652e636f6d300a06082a8648ce3d040302034800304502202b84814d7121"
    hex += "a5e9cccb48f07948d7755d851c7db72aee5f73313140f75523fc022100d724b7"
    hex += "f4284f765e08185f95f245313a8ab3eabb34a40967c6d182ec479254c1"
    return hex_to_bytes(hex)

fn test_parse_and_verify_cert() raises:
    var cert_der = cert_bytes()
    var cert = parse_certificate(cert_der)
    assert_equal(len(cert.tbs) > 0, True)
    assert_equal(len(cert.public_key), 65)
    assert_equal(verify_certificate_signature(cert), True)

fn test_chain_and_hostname() raises:
    var cert_der = cert_bytes()
    var cert = parse_certificate(cert_der)
    var hostname = hex_to_bytes("6578616d706c652e636f6d")
    var bad_hostname = hex_to_bytes("6261642e6578616d706c652e636f6d")
    assert_equal(hostname_matches(cert, hostname), True)
    var trust = TrustStore()
    trust.add_der(cert_der)
    assert_equal(verify_chain(cert_der, trust, hostname), True)
    assert_equal(verify_chain(cert_der, trust, bad_hostname), False)

fn main() raises:
    test_parse_and_verify_cert()
    test_chain_and_hostname()
