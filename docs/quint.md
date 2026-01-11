# Quint Tutorial: Spec-Based Development for ssl.mojo

Quint allows us to create formal specifications that can be simulated, model-checked, and tested. This document explains how we use Quint in this project to find logical flaws before writing implementation code.

## What is Quint?

Quint allows you to create **executable specifications**. It helps you find "design bugs" (logical flaws in your protocol) before you write a single line of implementation code.

## Basic Concepts

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

### Invariants (Safety)
Invariants are properties that must **always** be true. They check that "something bad never happens". If Quint finds a state where an invariant is false, it has found a bug in your design.
```quint
val AuthInvariant = (state == "LOGGED_IN") implies authenticated
```

### Temporal Properties (Liveness)
Liveness properties assert that "something good eventually happens". They are defined using temporal operators:
- `eventually(P)`: `P` will be true at some point in the current or a future state.
- `always(eventually(P))`: `P` will keep happening infinitely often.
- `always(P implies eventually(Q))`: If `P` occurs, `Q` must follow at some point.

Example:
```quint
temporal EventuallyTerminates = eventually(validation_status != Pending)
```

### Liveness Verification Mechanism
Quint verifies liveness properties via the **Apalache** model checker using a **Liveness-to-Safety Transformation**:

1.  **Lasso Finding**: A liveness property is disproven by finding a "Lasso"—a trace that enters a loop where the desired "good thing" never occurs.
2.  **Symbolic Proof**: Apalache transforms the temporal property into a safety invariant on an augmented state space. It then uses an SMT solver to prove that no Lasso exists for any possible execution path.
3.  **Bounded Checking**: Verification is performed up to a specific number of steps (default 10). If no counterexample is found, the property holds for all paths within that bound.

### Runs (`run`)
Runs are used for simulation. They define a sequence of actions (a "trace") to verify that a specific path is possible.
```quint
run HappyPath = Init.then(Authenticate)
```
Notes for simulation:
- `--max-steps` only limits trace length; it does not pick a specific scenario.
- Without `--run`, the simulator can choose any enabled action; traces can vary if there are multiple actions.
- For deterministic tests, also set `--max-samples 1` and a fixed `--seed`.
- Use `--run` when you need a specific path rather than "any valid path".

## Creating a Specification

To create a spec (like our `specs/tls13_protocol.qnt`):
1.  **Define the State**: What variables are needed to describe the system? (e.g., handshake step, keys derived).
2.  **Define Initialization**: What is the starting state? (`Init` action).
3.  **Define Transitions**: What events can happen? (e.g., `ReceiveClientHello`, `DeriveTrafficKeys`).
4.  **Define Safety**: What should *never* happen? (e.g., sending application data before the handshake is finished).

## Tooling & Dependencies

The Quint toolchain uses different backends depending on the task:

### Native (No Java required)
These commands run using the native TypeScript engine (or the experimental Rust backend) and do not require a JVM:
- **`quint run`**: Randomized simulation and invariant checking.
- **`quint test`**: Execution of `run` blocks and unit tests.
- **`quint compile`**: Syntax and type checking.
- **`quint format`**: Code linting and formatting.

### Formal Verification (Requires Java/JVM)
Formal verification relies on the **Apalache** symbolic model checker, which is a Java application:
- **`quint verify`**: Proving safety invariants and temporal properties for ALL possible paths using SMT solvers (Z3). 
- **Lasso Finding**: Any deep search for infinite loops or formal proofs of liveness.

**Note:** The first time you execute `quint verify`, the tool will automatically attempt to download the Apalache JAR if it is not found in your environment.

## Spec-Based Development Workflow

In `ssl.mojo`, we follow these steps:

1.  **Model**: Write the protocol logic in `.qnt` files in the `specs/` directory.
2.  **Verify**: Use the Quint CLI to simulate or formally verify the spec:
    ```bash
    # Simulation (Random paths)
    npx quint run --max-steps 25 specs/pki_path_validation.qnt

    # Formal Verification (Safety)
    npx quint verify --invariant IntermediatesMustBeCA specs/pki_path_validation.qnt

    # Formal Verification (Liveness)
    npx quint verify --temporal EventuallyTerminates specs/pki_path_validation.qnt
    ```
3.  **Check**: Use the Apalache model checker (via Quint) to prove invariants hold for all possible execution paths.
4.  **Implement**: Use the verified Quint spec as a "Golden Model" for the Mojo implementation in `src/`. The logic in `src/tls/handshake.mojo` should directly reflect the transitions defined in `specs/tls13_protocol.qnt`.
5.  **Test**: Generate test vectors from Quint traces to verify the Mojo implementation behaves exactly like the specification.