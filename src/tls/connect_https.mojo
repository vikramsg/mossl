"""HTTPS connector using TLSSocket handshake gating (Stage 5)."""
from lightbug_http.address import TCPAddr
from lightbug_http.socket import Socket

from tls.tls_socket import TLSSocket, SocketTransport

fn connect_https(
    host: String, port: UInt16
) raises -> TLSSocket[SocketTransport]:
    var socket = Socket[TCPAddr]()
    socket.connect(host, port)
    var tls = TLSSocket[SocketTransport](SocketTransport(socket^), host)
    try:
        if not tls.perform_handshake():
            tls.teardown()
            raise Error("connect_https: Handshake failed.")
    except e:
        tls.teardown()
        raise e
    return tls^
