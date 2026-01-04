from testing import assert_equal
from collections import List
from pki.pem import parse_pem

fn test_multiple_certs() raises:
    var data = (
        "Some text before\n"
        "-----BEGIN CERTIFICATE-----\n"
        "CERT1\n"
        "-----END CERTIFICATE-----\n"
        "Some text between\n"
        "-----BEGIN CERTIFICATE-----\n"
        "CERT2\n"
        "-----END CERTIFICATE-----\n"
        "Some text after"
    )
    
    var blocks = parse_pem(data)
    assert_equal(len(blocks), 2)
    assert_equal(blocks[0].strip(), "CERT1")
    assert_equal(blocks[1].strip(), "CERT2")

fn test_no_certs() raises:
    var blocks = parse_pem("no certs here")
    assert_equal(len(blocks), 0)

fn main() raises:
    test_multiple_certs()
    test_no_certs()

