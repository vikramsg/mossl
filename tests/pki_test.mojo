from src.pki.x509 import Certificate, verify_certificate

fn main() raises:
    let cert_ok = Certificate("httpbin.org", "payload", "sig:payload")
    assert(verify_certificate(cert_ok, "httpbin.org"), "valid cert should pass")

    let cert_bad = Certificate("example.com", "payload", "sig:payload")
    assert(not verify_certificate(cert_bad, "httpbin.org"), "hostname mismatch should fail")
