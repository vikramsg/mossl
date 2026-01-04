"""Toy TLSSocket wrapper with handshake gating."""

struct TLSSocket:
    var handshake_complete: Bool

fn new_tls_socket() -> TLSSocket:
    return TLSSocket(False)

fn connect_https(sock: TLSSocket, host: String) -> TLSSocket:
    // Toy handshake: mark as complete without network I/O.
    sock.handshake_complete = True
    return sock

fn can_send(sock: TLSSocket) -> Bool:
    return sock.handshake_complete
