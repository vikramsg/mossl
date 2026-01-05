from testing import assert_equal

from tls.handshake import HandshakeEngine

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.


fn test_valid_handshake_sequence() raises:
    var hs = HandshakeEngine()
    assert_equal(hs.can_send_application_data(), False)
    assert_equal(hs.send_client_hello(), True)
    assert_equal(hs.receive_server_flight(), True)
    assert_equal(hs.verify_certificate(True), True)
    assert_equal(hs.send_finished(), True)
    assert_equal(hs.handshake_complete(), True)
    assert_equal(hs.can_send_application_data(), True)


fn test_invalid_transition_rejected() raises:
    var hs = HandshakeEngine()
    assert_equal(hs.send_finished(), False)
    assert_equal(hs.receive_server_flight(), False)
    assert_equal(hs.verify_certificate(True), False)
    assert_equal(hs.send_client_hello(), True)
    assert_equal(hs.verify_certificate(True), False)
    assert_equal(hs.receive_server_flight(), True)
    assert_equal(hs.send_finished(), False)
    assert_equal(hs.verify_certificate(False), False)


fn main() raises:
    test_valid_handshake_sequence()
    test_invalid_transition_rejected()
