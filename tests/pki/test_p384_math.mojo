from collections import List
from testing import assert_true, assert_false, assert_equal

from pki.ecdsa_p384 import verify_ecdsa_p384_hash, U384

from crypto.bytes import hex_to_bytes
from crypto.sha384 import sha384_bytes


fn get_msg() -> List[UInt8]:
    return hex_to_bytes("48656c6c6f204d6f6a6f2042656e63686d61726b")


fn get_p384_pub() -> List[UInt8]:
    return hex_to_bytes(
        "04280d5497dec9fbda14637931d3a5ba60edca91ff2e9e5e9f5278acf10d371d5b2bd9e4ddc860c4c068cca7d5ca8db789129ca87576f9e0f9d172aa6061ab56ba36719c7a402c84d425da94646c105f1178326e9c323e79c87a7149bd990c4f6d"
    )


fn get_p384_sig() -> List[UInt8]:
    return hex_to_bytes(
        "3065023100d5132ebda8a826ce08208f819d7afd25aba53d94e316f86253ed0f547be7070368d089211e6e75c94ae9acb69847183d0230562e2b43b16cf7cf312b2e74d6b751c4144ca91579d1452cc9ea5ebdcd84f945445d9b338b232671fcd5003e74258058"
    )


fn test_p384_constants() raises:
    var p = U384.p384_p()
    # Check a few limbs
    assert_equal(p.l5, 0xFFFFFFFFFFFFFFFF)
    assert_equal(p.l0, 0x00000000FFFFFFFF)


fn test_verify_p384_valid() raises:
    var pub = get_p384_pub()
    var msg = get_msg()
    var sig = get_p384_sig()
    var digest = sha384_bytes(msg)

    var ok = verify_ecdsa_p384_hash(pub, digest, sig)
    assert_true(ok)


fn test_verify_p384_invalid_msg() raises:
    var pub = get_p384_pub()
    var msg = hex_to_bytes(
        "48656c6c6f204d6f6a6f2042656e63686d61726b21"
    )  # Changed message
    var sig = get_p384_sig()
    var digest = sha384_bytes(msg)

    var ok = verify_ecdsa_p384_hash(pub, digest, sig)
    assert_false(ok)


fn main() raises:
    test_p384_constants()
    test_verify_p384_valid()
    test_verify_p384_invalid_msg()
