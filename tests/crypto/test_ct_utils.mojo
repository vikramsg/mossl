from collections import List
from logger import Level, Logger
from testing import assert_true, assert_false, assert_equal

from crypto.bytes import constant_time_compare, ct_select, ct_swap


fn test_constant_time_compare() raises:
    var a = List[UInt8](1, 2, 3, 4)
    var b = List[UInt8](1, 2, 3, 4)
    var c = List[UInt8](1, 2, 0, 4)
    var d = List[UInt8](1, 2, 3)

    assert_true(constant_time_compare(a, b))
    assert_false(constant_time_compare(a, c))
    assert_false(constant_time_compare(a, d))


fn test_ct_select() raises:
    assert_equal(ct_select(0xFF, 10, 20), UInt8(10))
    assert_equal(ct_select(0x00, 10, 20), UInt8(20))


fn test_ct_swap() raises:
    var a = List[UInt8](1, 2, 3)
    var b = List[UInt8](4, 5, 6)

    # Choice 0: no swap
    ct_swap(a, b, 0)
    assert_equal(a[0], UInt8(1))
    assert_equal(b[0], UInt8(4))

    # Choice 1: swap
    ct_swap(a, b, 1)
    assert_equal(a[0], UInt8(4))
    assert_equal(b[0], UInt8(1))


fn main() raises:
    var log = Logger[Level.INFO]()
    test_constant_time_compare()
    test_ct_select()
    test_ct_swap()
    log.info("Constant-time utils tests passed!")
