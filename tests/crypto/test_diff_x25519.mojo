from collections import List

from python import Python
from tests.crypto.diff_utils import to_python_bytes, assert_equal_bytes

from crypto.x25519 import x25519


fn test_x25519_diff() raises:
    print("Testing X25519 differential with 1000 iterations...")
    var x25519_py = Python.import_module(
        "cryptography.hazmat.primitives.asymmetric.x25519"
    )
    var os = Python.import_module("os")

    var base_point = List[UInt8]()
    for i in range(32):
        if i == 0:
            base_point.append(9)
        else:
            base_point.append(0)

    for i in range(1000):
        # 1. Generate random private keys
        var priv_a_py = os.urandom(32)
        var priv_b_py = os.urandom(32)

        var priv_a_mojo = List[UInt8]()
        for j in range(32):
            priv_a_mojo.append(UInt8(Int(priv_a_py[j])))
        var priv_b_mojo = List[UInt8]()
        for j in range(32):
            priv_b_mojo.append(UInt8(Int(priv_b_py[j])))

        # 2. Compute public keys
        var pub_a_mojo = x25519(priv_a_mojo, base_point)
        var pub_b_mojo = x25519(priv_b_mojo, base_point)

        var py_priv_a = x25519_py.X25519PrivateKey.from_private_bytes(priv_a_py)
        var py_pub_a = py_priv_a.public_key().public_bytes_raw()

        var py_priv_b = x25519_py.X25519PrivateKey.from_private_bytes(priv_b_py)
        var py_pub_b = py_priv_b.public_key().public_bytes_raw()

        assert_equal_bytes(
            pub_a_mojo,
            py_pub_a,
            "X25519 PubA mismatch at iteration " + String(i),
        )
        assert_equal_bytes(
            pub_b_mojo,
            py_pub_b,
            "X25519 PubB mismatch at iteration " + String(i),
        )

        # 3. Compute shared secrets
        var shared_a_mojo = x25519(priv_a_mojo, pub_b_mojo)
        var shared_b_mojo = x25519(priv_b_mojo, pub_a_mojo)

        # They should be equal in Mojo
        for j in range(32):
            if shared_a_mojo[j] != shared_b_mojo[j]:
                raise Error(
                    "X25519 Mojo shared secrets mismatch at iteration "
                    + String(i)
                )

        var py_shared_a = py_priv_a.exchange(
            x25519_py.X25519PublicKey.from_public_bytes(py_pub_b)
        )
        assert_equal_bytes(
            shared_a_mojo,
            py_shared_a,
            "X25519 Shared mismatch at iteration " + String(i),
        )

        if i % 100 == 0:
            print("Iteration", i, "passed")

    print("X25519 differential test passed!")


fn main() raises:
    test_x25519_diff()
