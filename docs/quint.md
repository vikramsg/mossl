# Quint Tutorial: Spec-Based Development for ssl.mojo

Quint allows us to create formal specifications.
We will use Quint as a basis for doing spec-based development.

## 1. What is Quint?

Quint allows you to create **executable specifications**. 
Unlike a static document, a Quint spec can be simulated, model-checked, and tested. 
It helps you find "design bugs" (logical flaws in your protocol) before you write a single line of implementation code.

## 2. Basic Concepts

### Modules
Specifications are organized into modules.
```quint
module my_protocol {
  // logic goes here
}
```

### State Variables (`var`)
Variables represent the state of your system at any given point in time.
```quint
var state: str
var authenticated: bool
```

### Actions (`action`)
Actions define how the state can change. They are transitions.
- `all { ... }` means all conditions must be true (logical AND).
- `state' = ...` denotes the value of the variable in the *next* state.
- `state == ...` is a precondition.

```quint
action Authenticate = all {
    state == "IDLE",
    authenticated' = true,
    state' = "LOGGED_IN",
}
```

### Invariants
Invariants are properties that must **always** be true. If Quint finds a state where an invariant is false, it has found a bug in your design.
```quint
val AuthInvariant = (state == "LOGGED_IN") implies authenticated
```

### Runs (`run`)
Runs are used for simulation. They define a sequence of actions (a "trace") to verify that a specific path is possible.
```quint
run HappyPath = Init.then(Authenticate)
```

## 3. Creating a Specification

To create a spec (like our `specs/tls13_protocol.qnt`):
1.  **Define the State**: What variables are needed to describe the system? (e.g., handshake step, keys derived).
2.  **Define Initialization**: What is the starting state? (`Init` action).
3.  **Define Transitions**: What events can happen? (e.g., `ReceiveClientHello`, `DeriveTrafficKeys`).
4.  **Define Safety**: What should *never* happen? (e.g., sending application data before the handshake is finished).

## 4. Spec-Based Development Workflow

In `ssl.mojo`, we follow these steps:

1.  **Model**: Write the protocol logic in `.qnt` files in the `specs/` directory.
2.  **Verify**: Use the Quint CLI to simulate the spec:
    ```bash
    quint run specs/tls13_protocol.qnt
    ```
3.  **Check**: Use the Apalache model checker (via Quint) to prove invariants hold for all possible execution paths.
4.  **Implement**: Use the verified Quint spec as a "Golden Model" for the Mojo implementation in `src/`. The logic in `src/tls/handshake.mojo` should directly reflect the transitions defined in `specs/tls13_protocol.qnt`.
5.  **Test**: Generate test vectors from Quint traces to verify the Mojo implementation behaves exactly like the specification.

