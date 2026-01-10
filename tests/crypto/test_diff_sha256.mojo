from collections import List

from python import Python
from tests.crypto.diff_utils import to_python_bytes, assert_equal_bytes

from crypto.sha256 import sha256_bytes


fn test_sha256_diff() raises:
    print("Testing SHA-256 differential with 1000 iterations...")
    var hashlib = Python.import_module("hashlib")
    var os = Python.import_module("os")

    for i in range(1000):
        # Generate random length between 0 and 1000
        var length = Int(Python.import_module("random").randint(0, 1000))
        var py_data = os.urandom(length)

        # Convert to Mojo List[UInt8]
        var mojo_data = List[UInt8]()
        for j in range(length):
            mojo_data.append(UInt8(Int(py_data[j])))

        # Compute Mojo hash
        var mojo_hash = sha256_bytes(mojo_data)

        # Compute Python hash
        var py_hash_obj = hashlib.sha256(py_data)
        var py_hash = py_hash_obj.digest()

        assert_equal_bytes(
            mojo_hash, py_hash, "SHA-256 mismatch at iteration " + String(i)
        )

        if i % 100 == 0:
            print("Iteration", i, "passed")

    print("SHA-256 differential test passed!")


fn main() raises:
    test_sha256_diff()
