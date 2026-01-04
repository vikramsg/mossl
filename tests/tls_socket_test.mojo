from src.tls.socket import new_tls_socket, connect_https, can_send

fn main() raises:
    var sock = new_tls_socket()
    assert(not can_send(sock), "cannot send before handshake")
    sock = connect_https(sock, "httpbin.org")
    assert(can_send(sock), "can send after handshake")
