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
quint run --mbt --max-steps=10 --out-itf=trace.itf.json tcp_simple.qnt
```

This produces a JSON file that looks roughly like this:

```json
{
  "vars": ["client_state", "server_state", "mbt::actionTaken"],
  "states": [
    { 
      "#meta": { "index": 0 }, 
      "client_state": { "tag": "INIT" }, 
      "server_state": { "tag": "INIT" },
      "mbt::actionTaken": "Init"
    },
    { 
      "#meta": { "index": 1 }, 
      "client_state": { "tag": "SYN_SENT" }, 
      "server_state": { "tag": "INIT" },
      "mbt::actionTaken": "SendSyn"
    },
    ...
  ]
}
```

It captures the exact state of the system at every step.
Note that this is just *one* possible execution path. 
In the "Scaling Up" section below, we will discuss how to test against many random traces.

### Step 2: The Mojo Implementation

Now let's write our "production" code.
We need a struct that holds the state and methods that correspond to the actions in the spec.

```mojo
# tcp.mojo

struct State(EqualityComparable, ...): # Essentially an ENUM
    var _value: Int
    alias INIT = 0
    alias SYN_SENT = 1
    # ... other states ...

struct TCPModel:
    var client_state: State
    var server_state: State

    fn __init__(out self):
        self.client_state = State(State.INIT)
        self.server_state = State(State.INIT)

    # The implementation exactly mirrors the Quint spec
    fn send_syn(mut self) -> Bool:
        if self.client_state == State(State.INIT):
            self.client_state = State(State.SYN_SENT)
            return True
        return False

    # ... receive_syn, receive_syn_ack, etc.
```

This looks simple, but notice how the logic in `send_syn` mirrors the preconditions in the Quint spec?
If we messed up the `if` condition, the state transition wouldn't happen, or would happen at the wrong time.

### Step 3: The Replay Test

This is the magic glue. We write a test that reads the JSON trace and drives the Mojo model.

```mojo
# test_tcp.mojo (simplified)

fn main() raises:
    # 1. Load the Trace
    var trace = load_json("trace.itf.json")
    var states = trace["states"].array()

    # 2. Init Model
    var model = TCPModel()
    
    # 3. Iterate through the trace
    # Start at index 1 because index 0 is initial state
    for i in range(1, len(states)):
        var state = states[i]
        # Quint tells us exactly which action was taken!
        var action = state["mbt::actionTaken"].string()
        var success = False

        if action == "SendSyn":
            success = model.send_syn()
        elif action == "ReceiveSyn":
            success = model.receive_syn()
        # ... handle other actions ...
        
        if not success:
             raise Error("Action " + action + " failed at step " + String(i))
             
        # Verify state matches
        # ...

    print("Trace verified successfully!")
```

The test reads the action from the trace, executes it on the model, and asserts that the resulting state matches the spec.
If the implementation (Mojo) and the Spec (Quint) disagree, this test fails.

## Why is this powerful?

1.  **Fuzzing for Free**: Quint's random simulation generates edge cases we might forget to test manually.
2.  **Living Documentation**: The spec *is* the documentation, and the tests ensure the code respects it.
3.  **Refactoring Safety**: If we optimize the internals of `TCPModel`, as long as the external behavior (states) remains the same, the trace tests will pass.

### Scaling Up

In this simple TCP example, the logic is linear, so every random trace looks identical.
However, for complex protocols, we typically run this process in a loop (generating 100+ traces).
Since Quint picks random paths, this effectively fuzzes our Mojo implementation against the spec.

However, note that the scale of this approach has a limit. 
More complicated specs have many different trace paths.
And we cannot possibly test again all of them. 
But testing a sample of traces is definitely better than none. 

### What about Invariants?

You might ask: "Where are we checking the invariants (like `Safety`) in the Mojo test?"
Well, we don't, Quint does!
During the simulation phase, if a sequence of steps leads to a violation, 
Quint reports it as a `Violation Error`.
The job of the tracing test is purely to ensure that the code conforms to the spec.
And if the code matches the spec, then we will be reasonably confident that the code is correct.

### The Caveat: We still need Unit Tests

Formal methods are great for logic and state machines, but they don't replace unit tests entirely.
Specs often abstract away details.
For example, in TLS, the spec might say:

```quint
action Encrypt = {
  encrypted_data' = encrypt(data, key)
}
```

The spec assumes `encrypt` works mathematically.
It doesn't check if your AES-GCM implementation handles padding correctly, or if you have an off-by-one error in your buffer allocation.
For those lower-level implementation details, standard unit tests are still required.
We use formal methods to verify the orchestration and logic, and unit tests to verify the primitives.

## Conclusion

We've gone from a high-level requirement ("The connection must be safe") -> Formal spec (Quint) -> Verification (Model Checking) -> Concrete Implementation (A toy one but you get the point) -> Verified Code.

But how does this help us with AI (remember I mentioned it last time). 
Instead of struggling with English and producing concrete requirements,
we can collaborate with our favourite agent (mine is Opus 4.5 within Claude Code at the time of writing this post)
to produce a spec for the set of components we are building.
And if the tooling is in place, we can just tell the agent to build the component, 
and the trace tests will make sure we adhere to the spec.
