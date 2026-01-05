from collections import List
from testing import assert_equal

from lightbug_http.address import TCPAddr
from lightbug_http.io.bytes import Bytes, bytes
from memory import Span

from tls.tls_socket import TLSSocket
from tls.transport import TLSTransport


struct DummyTransport(Movable, TLSTransport):
    fn __init__(out self):
        pass

    fn read(self, mut buf: Bytes) raises -> Int:
        return 0

    fn write(self, buf: Span[Byte]) raises -> Int:
        return len(buf)

    fn close(mut self) raises:
        pass

    fn shutdown(mut self) raises -> None:
        pass

    fn teardown(mut self) raises:
        pass

    fn local_addr(self) -> TCPAddr:
        return TCPAddr(ip="127.0.0.1", port=0)

    fn remote_addr(self) -> TCPAddr:
        return TCPAddr(ip="127.0.0.1", port=0)


# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.


fn test_gating() raises:
    var transport = DummyTransport()
    var tls = TLSSocket[DummyTransport](transport^, "example.com")
    var ok = True
    try:
        _ = tls.write(bytes("hello"))
    except e:
        ok = False
    assert_equal(ok, False)

    tls.handshake_ok = True
    assert_equal(tls.can_send_application_data(), True)


fn main() raises:
    test_gating()
