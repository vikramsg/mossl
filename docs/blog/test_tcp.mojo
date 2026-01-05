from os import getenv
from tcp import TCPModel, State
import emberjson

fn main() raises:
    var trace_path = getenv("QUINT_TRACE_PATH")
    if trace_path == "":
        print("QUINT_TRACE_PATH not set, skipping trace verification")
        return

    var f = open(trace_path, "r")
    var content = f.read()
    f.close()

    var json = emberjson.parse(content)
    var states_val = json["states"].copy()
    var states = states_val.array().copy()

    # Initialize implementation
    var model = TCPModel()

    # Verify initial state matches trace[0]
    verify_state(model, states[0])
    print("Initial state verified.")

    # Iterate through transitions
    for i in range(len(states) - 1):
        var next_json = states[i+1].copy()
        var next_client_str = next_json["client_state"]["tag"].string()
        var next_server_str = next_json["server_state"]["tag"].string()

        var transitioned = False

        # Try SendSyn
        var m1 = model
        if m1.send_syn():
            if String(m1.client_state) == next_client_str and String(m1.server_state) == next_server_str:
                model = m1
                transitioned = True
                print("Step " + String(i) + " -> " + String(i+1) + ": SendSyn")

        if not transitioned:
            var m2 = model
            if m2.receive_syn():
                if String(m2.client_state) == next_client_str and String(m2.server_state) == next_server_str:
                    model = m2
                    transitioned = True
                    print("Step " + String(i) + " -> " + String(i+1) + ": ReceiveSyn")

        if not transitioned:
            var m3 = model
            if m3.receive_syn_ack():
                if String(m3.client_state) == next_client_str and String(m3.server_state) == next_server_str:
                    model = m3
                    transitioned = True
                    print("Step " + String(i) + " -> " + String(i+1) + ": ReceiveSynAck")

        if not transitioned:
            # Check for stutter (no state change)
            if String(model.client_state) == next_client_str and String(model.server_state) == next_server_str:
                print("Step " + String(i) + " -> " + String(i+1) + ": Stutter (No Change)")
                transitioned = True

        if not transitioned:
            raise Error("No valid transition found from state " + String(i) + " to " + String(i+1))

fn verify_state(model: TCPModel, state_json: emberjson.Value) raises:
    var client = state_json["client_state"]["tag"].string()
    var server = state_json["server_state"]["tag"].string()

    if String(model.client_state) != client:
        raise Error("Client state mismatch: " + String(model.client_state) + " != " + client)
    if String(model.server_state) != server:
        raise Error("Server state mismatch: " + String(model.server_state) + " != " + server)
