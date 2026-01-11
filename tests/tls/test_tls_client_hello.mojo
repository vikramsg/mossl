from collections import List
from testing import assert_equal

from tls.tls13 import (
    make_client_hello,
    ByteCursor,
    EXT_SIG_ALGS,
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PKCS1_SHA256,
    SIG_RSA_PKCS1_SHA384,
)


fn parse_sig_algs(ch: List[UInt8]) raises -> List[UInt16]:
    var cur = ByteCursor(ch)
    _ = cur.read_u16()  # legacy_version
    _ = cur.read_bytes(32)  # random
    var sid_len = Int(cur.read_u8())
    if sid_len > 0:
        _ = cur.read_bytes(sid_len)
    var cs_len = Int(cur.read_u16())
    if cs_len > 0:
        _ = cur.read_bytes(cs_len)
    var comp_len = Int(cur.read_u8())
    if comp_len > 0:
        _ = cur.read_bytes(comp_len)
    var ext_len = Int(cur.read_u16())
    var ext_bytes = cur.read_bytes(ext_len)
    var ext_cur = ByteCursor(ext_bytes)
    while ext_cur.remaining() > 0:
        var ext_type = ext_cur.read_u16()
        var ext_size = Int(ext_cur.read_u16())
        var ext_body = ext_cur.read_bytes(ext_size)
        if ext_type == EXT_SIG_ALGS:
            var sig_cur = ByteCursor(ext_body)
            var list_len = Int(sig_cur.read_u16())
            var out = List[UInt16]()
            var i = 0
            while i < list_len:
                out.append(sig_cur.read_u16())
                i += 2
            return out^
    return List[UInt16]()


fn contains(list: List[UInt16], v: UInt16) -> Bool:
    for i in range(len(list)):
        if list[i] == v:
            return True
    return False


fn test_client_hello_sigalgs() raises:
    var random = List[UInt8]()
    for _ in range(32):
        random.append(0)
    var pub = List[UInt8]()
    for _ in range(32):
        pub.append(1)
    var ch = make_client_hello("example.com", random, pub)
    var sigs = parse_sig_algs(ch)
    assert_equal(contains(sigs, SIG_ECDSA_SECP256R1_SHA256), True)
    assert_equal(contains(sigs, SIG_ECDSA_SECP384R1_SHA384), True)
    assert_equal(contains(sigs, SIG_RSA_PSS_RSAE_SHA256), True)
    assert_equal(contains(sigs, SIG_RSA_PKCS1_SHA256), True)
    assert_equal(contains(sigs, SIG_RSA_PKCS1_SHA384), True)


fn main() raises:
    test_client_hello_sigalgs()
