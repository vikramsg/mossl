# Introduction to Formal Methods (Part 2): From Spec to Code

In [Part 1](./intro-to-formal-methods-part-1.md), we talked about the "Why".
Why write a spec? Because English is ambiguous, and debugging design flaws in code is expensive.
We looked at **Quint** and modeled a simple TCP Handshake.
We verified that our logic was sound (no safety violations).

But as I hinted at the end of Part 1: a spec is just a file. 
If I go off and write code and ignore the spec, I haven't really gained anything.
In fact, I've just wasted time writing a spec.

In this part, we will close the loop.
We will use what is called Model-Based Testing to ensure our Mojo implementation behaves *exactly* like our verified spec.

## The Strategy: Trace Replay

We can't easily "compile" Quint to Mojo (yet).
And we probably don't want to, because the spec is an abstraction, not an implementation.
The spec doesn't care about memory management, sockets, or cache lines. 
The implementation does.

Instead, we treat the spec as a test case generator.

1.  First, generate a trace by using quint to run a simulation and save the sequence of steps (the trace) to a file.
2.  Then, we replay the trace in Mojo, but we instrument it so that it looks like a test.
3.  For every step in the trace (e.g., `SendSyn`), we execute the corresponding method in our Mojo struct.
4.  Finally, after each step, we check if our Mojo object's state matches the spec's state.

If the test passes, we know our code handles the scenarios defined by the spec correctly.

### Step 1: Generating the Trace

In Part 1, we ran `quint run` to see text output.
Now, we want a machine-readable format. 
Quint supports the **ITF** (Json Trace Format).

```bash
quint run --max-steps=10 --out-itf=trace.itf.json tcp_simple.qnt
```

This produces a JSON file that looks roughly like this:

```json
{
  "vars": ["client_state", "server_state"],
  "states": [
    { 
      "#meta": { "index": 0 }, 
      "client_state": { "tag": "INIT" }, 
      "server_state": { "tag": "INIT" } 
    },
    { 
      "#meta": { "index": 1 }, 
      "client_state": { "tag": "SYN_SENT" }, 
      "server_state": { "tag": "INIT" } 
    },
    ...
  ]
}
```

It captures the exact state of the system at every step.

### Step 2: The Mojo Implementation

Now let's write our "production" code.
We need a struct that holds the state and methods that correspond to the actions in the spec.

```mojo
// tcp.mojo

@fieldwise_init
struct State(Stringable, EqualityComparable, Copyable, ImplicitlyCopyable):
    var _value: Int
    alias INIT = 0
    alias SYN_SENT = 1
    alias SYN_RCVD = 2
    alias ESTABLISHED = 3
    
    # ... boiler plate for __str__, __eq__ ...

struct TCPModel(Copyable, ImplicitlyCopyable):
    var client_state: State
    var server_state: State

    fn __init__(out self):
        self.client_state = State(State.INIT)
        self.server_state = State(State.INIT)

    # Corresponds to action SendSyn
    fn send_syn(mut self) -> Bool:
        if self.client_state == State(State.INIT):
            self.client_state = State(State.SYN_SENT)
            return True
        return False

    # Corresponds to action ReceiveSyn
    fn receive_syn(mut self) -> Bool:
        if self.server_state == State(State.INIT) and 
           self.client_state == State(State.SYN_SENT):
            self.server_state = State(State.SYN_RCVD)
            return True
        return False

    # Corresponds to action ReceiveSynAck
    fn receive_syn_ack(mut self) -> Bool:
        if self.client_state == State(State.SYN_SENT):
            self.client_state = State(State.ESTABLISHED)
            return True
        return False
```

This looks simple, but notice how the logic in `send_syn` mirrors the preconditions in the Quint spec?
If we messed up the `if` condition, the state transition wouldn't happen, or would happen at the wrong time.

## Step 3: The Replay Test

This is the magic glue. We write a test that reads the JSON trace and drives the Mojo model.

```mojo
// test_tcp.mojo (simplified)

fn main() raises:
    # 1. Load the Trace
    var trace = load_json("trace.itf.json")
    var states = trace["states"].array()

    # 2. Init Model
    var model = TCPModel()
    
    # 3. Iterate through the trace
    for i in range(len(states) - 1):
        var next_state = states[i+1]
        var target_client = next_state["client_state"]["tag"].string()
        
        # 4. Try to find a valid transition
        var transitioned = False
        
        # Try "SendSyn"
        var m_temp = model
        if m_temp.send_syn():
            if str(m_temp.client_state) == target_client:
                model = m_temp
                transitioned = True
                print("Transition: SendSyn")

        # Try "ReceiveSyn" if needed...
        # Try "ReceiveSynAck" if needed...
        
        if not transitioned:
             raise Error("Implementation could not reproduce step " + str(i))

    print("Trace verified successfully!")
```

The test is "dumb". It doesn't know the logic.
It just tries to apply the methods on the model to see if it can reach the next state defined by the trace.
If the implementation (Mojo) and the Spec (Quint) disagree, this test fails.

## Why is this powerful?

1.  **Fuzzing for Free**: Quint's random simulation generates edge cases we might forget to test manually.
2.  **Living Documentation**: The spec *is* the documentation, and the tests ensure the code respects it.
3.  **Refactoring Safety**: If we optimize the internals of `TCPModel`, as long as the external behavior (states) remains the same, the trace tests will pass.

## Conclusion

We've gone from a high-level requirement ("The connection must be safe") -> TLA+ style logic (Quint) -> Verification (Model Checking) -> Concrete Implementation (Mojo) -> Verified Code.

This might seem like overkill for a simple handshake.
But for complex protocols (like TLS 1.3, Raft, or Byzantine Fault Tolerance), where the number of states explodes, this approach is a lifesaver.
It allows us to "think" in the spec and "build" in the code, with a machine-verified bridge in between.

In this project (`ssl.mojo`), we are using this exact methodology to implement TLS.
You can find the specs in the `specs/` folder and the corresponding trace tests in `tests/trace_config.json`.
