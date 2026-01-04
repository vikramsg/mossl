"""TLS socket wrapper with handshake gating for lightbug_http integration (Stage 5)."""
from collections import List
from memory import Span
from lightbug_http.connection import Connection
from lightbug_http.io.bytes import Bytes
from lightbug_http.address import TCPAddr
from lightbug_http.socket import Socket
from tls.handshake import HandshakeEngine

trait TLSTransport(Movable):
    fn read(self, mut buf: Bytes) raises -> Int:
        ...

    fn write(self, buf: Span[Byte]) raises -> Int:
        ...

    fn close(mut self) raises:
        ...

    fn shutdown(mut self) raises -> None:
        ...

    fn teardown(mut self) raises:
        ...

    fn local_addr(self) -> TCPAddr:
        ...

    fn remote_addr(self) -> TCPAddr:
        ...


struct SocketTransport(TLSTransport):
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


struct NullTransport(TLSTransport):
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


struct TLSSocket[T: TLSTransport](Connection):
    var transport: T
    var handshake: HandshakeEngine

    fn __init__(out self, var transport: T):
        self.transport = transport^
        self.handshake = HandshakeEngine()

    fn perform_handshake(mut self) -> Bool:
        if not self.handshake.send_client_hello():
            return False
        if not self.handshake.receive_server_flight():
            return False
        if not self.handshake.verify_certificate(True):
            return False
        if not self.handshake.send_finished():
            return False
        return self.handshake.handshake_complete()

    fn can_send_application_data(self) -> Bool:
        return self.handshake.can_send_application_data()

    fn read(self, mut buf: Bytes) raises -> Int:
        if not self.handshake.can_send_application_data():
            raise Error("TLSSocket.read: Handshake not complete.")
        return self.transport.read(buf)

    fn write(self, buf: Span[Byte]) raises -> Int:
        if not self.handshake.can_send_application_data():
            raise Error("TLSSocket.write: Handshake not complete.")
        return self.transport.write(buf)

    fn close(mut self) raises:
        self.transport.close()

    fn shutdown(mut self) raises -> None:
        self.transport.shutdown()

    fn teardown(mut self) raises:
        self.transport.teardown()

    fn local_addr(self) -> TCPAddr:
        return self.transport.local_addr()

    fn remote_addr(self) -> TCPAddr:
        return self.transport.remote_addr()
