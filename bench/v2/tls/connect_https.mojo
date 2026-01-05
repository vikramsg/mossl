from lightbug_http.address import TCPAddr
from lightbug_http.socket import Socket
from time import perf_counter

from tls.tls_socket import TLSSocket, SocketTransport

struct Timer:
    var start: Float64
    var name: String

    fn __init__(out self, name: String):
        self.name = name
        self.start = perf_counter()
        print("    [DEBUG] Starting " + self.name)

    fn stop(self):
        var end = perf_counter()
        print("    [CONN-TIMER] " + self.name + ": " + String(end - self.start) + "s")

fn connect_https(
    host: String, port: UInt16
) raises -> TLSSocket[SocketTransport]:
    var t_total = Timer("connect_https_total")
    var socket = Socket[TCPAddr]()
    socket.connect(host, port)
    var tls = TLSSocket[SocketTransport](SocketTransport(socket^), host)
    try:
        var t_hs = Timer("perform_handshake")
        if not tls.perform_handshake():
            tls.teardown()
            raise Error("connect_https: Handshake failed.")
        t_hs.stop()
    except e:
        tls.teardown()
        raise e
    t_total.stop()
    return tls^