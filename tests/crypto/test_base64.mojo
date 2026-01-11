from collections import List
from testing import assert_equal

from crypto.base64 import base64_decode

fn test_rfc4648_vectors() raises:
    assert_equal(len(base64_decode("")), 0)

    var res1 = base64_decode("Zg==")
    assert_equal(len(res1), 1)
    assert_equal(res1[0], ord("f"))

    var res2 = base64_decode("Zm8=")
    assert_equal(len(res2), 2)
    assert_equal(res2[0], ord("f"))
    assert_equal(res2[1], ord("o"))

    var res3 = base64_decode("Zm9v")
    assert_equal(len(res3), 3)
    assert_equal(res3[0], ord("f"))
    assert_equal(res3[1], ord("o"))
    assert_equal(res3[2], ord("o"))

    var res4 = base64_decode("Zm9vYg==")
    assert_equal(len(res4), 4)
    assert_equal(res4[0], ord("f"))
    assert_equal(res4[1], ord("o"))
    assert_equal(res4[2], ord("o"))
    assert_equal(res4[3], ord("b"))

    var res5 = base64_decode("Zm9vYmE=")
    assert_equal(len(res5), 5)
    assert_equal(res5[0], ord("f"))
    assert_equal(res5[1], ord("o"))
    assert_equal(res5[2], ord("o"))
    assert_equal(res5[3], ord("b"))
    assert_equal(res5[4], ord("a"))

    var res6 = base64_decode("Zm9vYmFy")
    assert_equal(len(res6), 6)
    assert_equal(res6[0], ord("f"))
    assert_equal(res6[1], ord("o"))
    assert_equal(res6[2], ord("o"))
    assert_equal(res6[3], ord("b"))
    assert_equal(res6[4], ord("a"))
    assert_equal(res6[5], ord("r"))


fn test_with_whitespace() raises:
    # PEM files often have newlines
    var res = base64_decode("Zm9v\nYmFy")
    assert_equal(len(res), 6)
    assert_equal(res[0], ord("f"))
    assert_equal(res[5], ord("r"))


fn main() raises:
    test_rfc4648_vectors()
    test_with_whitespace()
