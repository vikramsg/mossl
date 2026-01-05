"""TLS socket wrapper with handshake gating for lightbug_http integration (Stage 5)."""
from collections import List

from lightbug_http.address import TCPAddr
from lightbug_http.io.bytes import Bytes
from lightbug_http.socket import Socket
from memory import Span

from tls.tls13 import TLS13Client
from tls.transport import TLSTransport

struct SocketTransport(Movable, TLSTransport):
    var socket: Socket[TCPAddr]

    fn __init__(out self, var socket: Socket[TCPAddr]):
        self.socket = socket^

    fn read(self, mut buf: Bytes) raises -> Int:
        return Int(self.socket.receive(buf))

    fn write(self, buf: Span[Byte]) raises -> Int:
        return Int(self.socket.send(buf))

    fn close(mut self) raises:
        self.socket.close()

    fn shutdown(mut self) raises -> None:
        self.socket.shutdown()

    fn teardown(mut self) raises:
        self.socket.teardown()

    fn local_addr(self) -> TCPAddr:
        return self.socket.local_address()

    fn remote_addr(self) -> TCPAddr:
        return self.socket.remote_address()


struct NullTransport(Movable, TLSTransport):
    var local: TCPAddr
    var remote: TCPAddr

    fn __init__(out self):
        self.local = TCPAddr(ip="127.0.0.1", port=0)
        self.remote = TCPAddr(ip="127.0.0.1", port=0)

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
        return self.local

    fn remote_addr(self) -> TCPAddr:
        return self.remote


struct TLSSocket[T: TLSTransport](Movable):
    var tls: TLS13Client[T]
    var handshake_ok: Bool

    fn __init__(out self, var transport: T, host: String):
        self.tls = TLS13Client[T](transport^, host)
        self.handshake_ok = False

    fn perform_handshake(mut self) raises -> Bool:
        var ok = self.tls.perform_handshake()
        self.handshake_ok = ok
        return ok

    fn can_send_application_data(self) -> Bool:
        return self.handshake_ok

    fn read(mut self, mut buf: Bytes) raises -> Int:
        if not self.handshake_ok:
            raise Error("TLSSocket.read: Handshake not complete.")
        var data = self.tls.read_app_data()
        while len(buf) > 0:
            _ = buf.pop()
        for b in data:
            buf.append(Byte(b))
        return len(buf)

    fn write(mut self, buf: Span[Byte]) raises -> Int:
        if not self.handshake_ok:
            raise Error("TLSSocket.write: Handshake not complete.")
        var out = List[UInt8]()
        for b in buf:
            out.append(UInt8(b))
        self.tls.write_app_data(out)
        return len(buf)

    fn close(mut self) raises:
        self.tls.transport.close()

    fn shutdown(mut self) raises -> None:
        self.tls.transport.shutdown()

    fn teardown(mut self) raises:
        self.tls.transport.teardown()

    fn local_addr(self) -> TCPAddr:
        return self.tls.transport.local_addr()

    fn remote_addr(self) -> TCPAddr:
        return self.tls.transport.remote_addr()
