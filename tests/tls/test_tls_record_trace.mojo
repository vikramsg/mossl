from collections import List
from os import getenv
from testing import assert_equal

import emberjson

from crypto.bytes import hex_to_bytes
from tls.record_layer import RecordSealer

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.


fn test_record_layer_trace() raises:
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
    var key = hex_to_bytes("00112233445566778899aabbccddeeff")
    var iv = hex_to_bytes("000000000000000000000000")
    var sealer = RecordSealer(key, iv)

    # 3. Iterate and verify
    for i in range(len(states)):
        var state = states[i].copy()
        var expected_seq_str = state["sequence"].copy()["#bigint"].string()
        var expected_seq = Int(expected_seq_str)

        # Verify current state
        assert_equal(sealer.seq, UInt64(expected_seq))

        # Transition (if not at the end)
        if i < len(states) - 1:
            # We call seal to increment sequence
            _ = sealer.seal(List[UInt8](), List[UInt8]())


fn main() raises:
    test_record_layer_trace()
