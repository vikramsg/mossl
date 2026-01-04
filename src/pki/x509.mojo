"""Toy X.509 parsing and verification helpers."""

struct Certificate:
    var hostname: String
    var payload: String
    var signature: String

fn verify_hostname(cert: Certificate, expected: String) -> Bool:
    return cert.hostname == expected

fn verify_signature(cert: Certificate) -> Bool:
    return cert.signature == ("sig:" + cert.payload)

fn verify_certificate(cert: Certificate, expected_host: String) -> Bool:
    return verify_hostname(cert, expected_host) and verify_signature(cert)
