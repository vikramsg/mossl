"""Toy TLS 1.3 handshake state machine for contract tests."""
from src.crypto.hkdf import hkdf_extract, hkdf_expand
from src.pki.x509 import Certificate, verify_certificate

struct Handshake:
    var state: String
    var key_schedule_ready: Bool
    var cert_verified: Bool

fn new_handshake() -> Handshake:
    return Handshake("start", False, False)

fn send_client_hello(hs: Handshake) -> Handshake:
    if hs.state == "start":
        hs.state = "client_hello"
    return hs

fn receive_server_hello(hs: Handshake) -> Handshake:
    if hs.state == "client_hello":
        hs.state = "server_hello"
    return hs

fn compute_key_schedule(hs: Handshake) -> Handshake:
    if hs.state == "server_hello":
        let prk = hkdf_extract("salt", "ikm")
        let _okm = hkdf_expand(prk, "info", 32)
        hs.key_schedule_ready = True
    return hs

fn receive_certificate(hs: Handshake) -> Handshake:
    if hs.state == "server_hello":
        hs.state = "cert_received"
    return hs

fn verify_cert(hs: Handshake, cert: Certificate, host: String) -> Handshake:
    if hs.state == "cert_received" and verify_certificate(cert, host):
        hs.cert_verified = True
    return hs

fn receive_server_finished(hs: Handshake) -> Handshake:
    if hs.state == "cert_received":
        hs.state = "server_finished"
    return hs

fn send_client_finished(hs: Handshake) -> Handshake:
    if hs.state == "server_finished" and hs.key_schedule_ready and hs.cert_verified:
        hs.state = "handshake_complete"
    return hs
