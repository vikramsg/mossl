from collections import List
from python import Python
from crypto.x25519 import x25519
from tests.crypto.diff_utils import assert_equal_bytes
from memory import Span

fn test_x25519_diff() raises:
    print("Testing X25519 differential with 1000 iterations...")
    var x25519_py = Python.import_module("cryptography.hazmat.primitives.asymmetric.x25519")
    var os = Python.import_module("os")

    for i in range(1000):
        var a_priv_py = x25519_py.X25519PrivateKey.generate()
        var a_pub_py = a_priv_py.public_key()
        var b_priv_py = x25519_py.X25519PrivateKey.generate()
        var b_pub_py = b_priv_py.public_key()

        var a_priv_bytes = a_priv_py.private_bytes_raw()
        var b_pub_bytes = b_pub_py.public_bytes_raw()

        var a_priv = List[UInt8]()
        for j in range(32):
            a_priv.append(UInt8(Int(a_priv_bytes[j])))
        var b_pub = List[UInt8]()
        for j in range(32):
            b_pub.append(UInt8(Int(b_pub_bytes[j])))

        var got = x25519(a_priv, b_pub)
        var want = a_priv_py.exchange(b_pub_py)

        assert_equal_bytes(got, want, "X25519 mismatch at iteration " + String(i))

        if i % 100 == 0:
            print("Iteration", i, "passed")
    print("X25519 differential test passed!")

fn main() raises:
    test_x25519_diff()