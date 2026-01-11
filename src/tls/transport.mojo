"""Transport trait for TLS I/O."""
from lightbug_http.address import TCPAddr
from lightbug_http.io.bytes import Bytes
from memory import Span

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
