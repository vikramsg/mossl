from os import getenv
from testing import assert_equal

import emberjson

from tls.handshake import HandshakeEngine

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.


fn test_handshake_trace() raises:
    # 1. Load the trace
    var trace_path = getenv("QUINT_TRACE_PATH", "trace.json")
    var f = open(trace_path, "r")
    var trace_str = f.read()
    f.close()

    var trace_json = emberjson.parse(trace_str)
    var states_val = trace_json["states"].copy()
    if not states_val.is_array():
        raise Error("Expected states to be an array")

    var states = states_val.array().copy()

    # 2. Setup the Mojo implementation
    var handshake = HandshakeEngine()

    # 3. Iterate and verify
    for i in range(len(states)):
        var state = states[i].copy()
        var expected_state_str = state["state"].copy()["#bigint"].string()
        var expected_state = Int(expected_state_str)
        var expected_verified_str = state["verified"].copy()["#bigint"].string()
        var expected_verified = Int(expected_verified_str)
        var expected_verified_bool = expected_verified == Int(1)

        # Verify current state
        assert_equal(handshake.state, expected_state)
        assert_equal(handshake.verified, expected_verified_bool)

        # Transition (if not at the end)
        if i < len(states) - 1:
            if expected_state == Int(0):
                assert_equal(handshake.send_client_hello(), True)
            elif expected_state == Int(1):
                assert_equal(handshake.receive_server_flight(), True)
            elif expected_state == Int(2):
                assert_equal(handshake.verify_certificate(True), True)
            elif expected_state == Int(3):
                assert_equal(handshake.send_finished(), True)
            else:
                raise Error("Unexpected handshake state in trace")


fn main() raises:
    test_handshake_trace()
