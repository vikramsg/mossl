from src.tls.handshake import new_handshake, send_client_hello, receive_server_hello
from src.tls.handshake import compute_key_schedule, receive_certificate, verify_cert
from src.tls.handshake import receive_server_finished, send_client_finished
from src.pki.x509 import Certificate

fn main() raises:
    var hs = new_handshake()
    hs = send_client_hello(hs)
    hs = receive_server_hello(hs)
    hs = compute_key_schedule(hs)
    hs = receive_certificate(hs)

    let cert = Certificate("httpbin.org", "payload", "sig:payload")
    hs = verify_cert(hs, cert, "httpbin.org")
    hs = receive_server_finished(hs)
    hs = send_client_finished(hs)

    assert(hs.state == "handshake_complete", "handshake should complete on happy path")
