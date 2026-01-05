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

    # Initialize implementation (Corresponds to action "Init")
    var model = TCPModel()

    # Verify initial state matches trace[0]
    verify_state(model, states[0])
    print("Initial state verified.")

    # Iterate through transitions
    # trace[0] is initial state.
    # trace[1] is the result of the first transition action.
    for i in range(1, len(states)):
        var state_json = states[i].copy()

        # With --mbt, the trace tells us exactly which action was taken!
        var action = state_json["mbt::actionTaken"].string()

        print("Step " + String(i) + ": Applying " + action)

        var success = False
        if action == "SendSyn":
            success = model.send_syn()
        elif action == "ReceiveSyn":
            success = model.receive_syn()
        elif action == "ReceiveSynAck":
            success = model.receive_syn_ack()
        else:
            raise Error("Unknown or unhandled action in trace: " + action)

        if not success:
             raise Error("Action " + action + " returned False (precondition failed) at step " + String(i))

        # Verify state matches the trace
        verify_state(model, state_json)

fn verify_state(model: TCPModel, state_json: emberjson.Value) raises:
    var client = state_json["client_state"]["tag"].string()
    var server = state_json["server_state"]["tag"].string()

    if String(model.client_state) != client:
        raise Error("Client state mismatch: " + String(model.client_state) + " != " + client)
    if String(model.server_state) != server:
        raise Error("Server state mismatch: " + String(model.server_state) + " != " + server)
