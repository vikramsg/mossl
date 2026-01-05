from os import path
from testing import assert_equal, assert_true

from pki.x509 import TrustStore, load_system_trust_store


fn test_trust_store_load_pem() raises:
    var pem = (
        "-----BEGIN CERTIFICATE-----\nTW9qbw==\n-----END CERTIFICATE-----\n"
    )
    var trust = TrustStore()
    trust.load_pem(pem)
    assert_equal(len(trust.roots), 1)
    # "Mojo" in base64 is TW9qbw==
    assert_equal(len(trust.roots[0]), 4)
    assert_equal(trust.roots[0][0], ord("M"))


fn test_system_trust_store() raises:
    var trust = load_system_trust_store()
    # On most linux systems this should load something
    # If it's a very stripped down environment it might be empty,
    # but in devcontainer it should have certs.
    # print("Loaded", len(trust.roots), "system certificates")
    assert_true(len(trust.roots) > 0)


fn main() raises:
    test_trust_store_load_pem()
    test_system_trust_store()
