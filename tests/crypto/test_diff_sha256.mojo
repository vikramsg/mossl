from collections import List

from memory import Span
from python import Python
from tests.crypto.diff_utils import assert_equal_bytes

from crypto.sha256 import sha256


fn test_sha256_diff() raises:
    print("Testing SHA-256 differential with 1000 iterations...")
    var hashlib = Python.import_module("hashlib")
    var os = Python.import_module("os")
    var random = Python.import_module("random")

    for i in range(1000):
        var data_len = Int(random.randint(0, 1000))
        var data_py = os.urandom(data_len)
        var data = List[UInt8]()
        for j in range(data_len):
            data.append(UInt8(Int(data_py[j])))

        var got_arr = sha256(data)
        var got = List[UInt8]()
        for j in range(32):
            got.append(got_arr[j])
        var want = hashlib.sha256(data_py).digest()

        assert_equal_bytes(
            got, want, "SHA-256 mismatch at iteration " + String(i)
        )

        if i % 100 == 0:
            print("Iteration", i, "passed")
    print("SHA-256 differential test passed!")


fn main() raises:
    test_sha256_diff()
