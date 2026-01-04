from collections import List
from testing import assert_equal

from lightbug_http.io.bytes import bytes

from tls.tls_socket import TLSSocket, NullTransport

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.


fn test_gating() raises:
    var tls = TLSSocket[NullTransport](NullTransport())
    var ok = True
    try:
        _ = tls.write(bytes("hello"))
    except e:
        ok = False
    assert_equal(ok, False)

    assert_equal(tls.perform_handshake(), True)

    ok = True
    try:
        _ = tls.write(bytes("hello"))
    except e:
        ok = False
    assert_equal(ok, True)


fn main() raises:
    test_gating()
