from collections import List
from testing import assert_equal, assert_true

from logger import Level, Logger

from tls.tls13 import random_bytes


fn test_random_bytes() raises:
    var log = Logger[Level.INFO]()
    log.info("Testing random_bytes...")
    var n = 32
    var b1 = random_bytes(n)
    assert_equal(len(b1), n)

    var b2 = random_bytes(n)
    assert_equal(len(b2), n)

    # Check that two calls don't return same data (very high probability)
    var identical = True
    for i in range(n):
        if b1[i] != b2[i]:
            identical = False
            break
    assert_true(not identical, "random_bytes returned identical data")
    log.info("random_bytes test passed!")


fn main() raises:
    test_random_bytes()
