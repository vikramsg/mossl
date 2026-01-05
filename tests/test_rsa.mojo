from collections import List
from testing import assert_true, assert_equal

from pki.rsa import verify_rsa_pkcs1v15

from crypto.bytes import hex_to_bytes


fn test_rsa_verification() raises:
    # A simple 1024-bit RSA public key (modulus n, exponent e=65537)
    # n (128 bytes)
    var n_hex = "00c360c6d9446d6a2f8d22742911b9e1191caef22a94464b5f8d22742911b9e1191caef22a94464b5f8d22742911b9e1191caef22a94464b5f8d22742911b9e1191caef22a94464b5f8d22742911b9e1191caef22a94464b5f8d22742911b9e1191caef22a94464b5f8d22742911b9e1191caef22a94464b5f8d22742911b9e1"
    # Wait, the above is fake. Let's use a real vector.
    # Actually, let's first fix x509.mojo to delegate to RSA.
    pass


fn main() raises:
    # test_rsa_verification()
    print("RSA test script placeholder")
