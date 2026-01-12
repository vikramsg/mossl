# Proposal: Typestate Pattern for PKI Validation

This document outlines a strategy to make invalid states unrepresentable in the Mojo PKI implementation by leveraging Mojo's ownership model and the `utils.Variant` type.

## Current State (Status-as-Value)

The current POC in `poc/pki_validation.mojo` uses a "Product Type" approach:
- A single `PKIValidator` struct holds all possible data fields (`step`, `status`, `chain`, etc.).
- The `status` is a value that changes over time.
- **Risk**: It is possible to have a `status == VALID` while `step < len(chain)`, which is a logically inconsistent state.

## Proposed State (Typestate Pattern)

By using the Typestate pattern, we encode the state of the validation process into the type system itself.

### 1. Define State-Specific Structs

Each state only holds the data necessary for that specific phase of the lifecycle.

```mojo
struct ValidationInProgress:
    var step: Int
    var chain: List[MockCertificate]

struct ValidationSuccess:
    var validated_chain: List[MockCertificate]

struct ValidationFailure:
    var error: ValidationStatus # e.g., EXPIRED, SIGNATURE_FAILURE
    var step: Int
```

### 2. Represent the State Machine as a Variant

The `Validator` becomes a wrapper around a `Variant` of these states.

```mojo
alias ValidatorState = Variant[
    ValidationInProgress,
    ValidationSuccess,
    ValidationFailure
]
```

### 3. Transitions via Ownership Transfer (`var`)

To transition between states, we use the `var` convention (formerly `owned`). This allows the function to consume the current state and return a new one. The transfer operator `^` ensures the old state cannot be used again.

```mojo
fn validate_next_step(var current: ValidationInProgress) -> ValidatorState:
    """Consumes the current state and returns the next valid state."""
    # Logic to validate the current step...
    if error_found:
        return ValidatorState(ValidationFailure(ValidationStatus.EXPIRED, current.step))
    
    if current.step + 1 == len(current.chain):
        return ValidatorState(ValidationSuccess(current.chain))
        
    return ValidatorState(ValidationInProgress(current.step + 1, current.chain))
```

### 4. Comparison of Argument Conventions

| Convention | Description | Use Case in Typestate |
| :--- | :--- | :--- |
| `read` (default) | Immutable reference. | Inspecting state (e.g., `is_finished()`). |
| `mut` | Mutable reference. | In-place updates that don't change the state type. |
| `var` | Ownership transfer. | **State Transitions**: Consuming one state to produce another. |

## Benefits

1. **Safety**: Invalid states (like a successful validation with missing steps) are physically impossible to construct.
2. **Exhaustiveness**: The compiler (via `isa[T]`) forces the developer to handle all possible outcomes of a transition (Success, Failure, or InProgress).
3. **Performance**: Mojo's `Variant` is memory-efficient (size of the largest struct + tag) and `var` transfers avoid expensive deep copies of the certificate chain.

## Example Usage

```mojo
var state = ValidatorState(ValidationInProgress(0, cert_chain))

# In a loop or event handler:
if state.isa[ValidationInProgress]():
    # Consume 'state' and replace it with the result of the transition
    state = validate_next_step(state.unsafe_take[ValidationInProgress]()^)

if state.isa[ValidationSuccess]():
    print("Validation Complete!")
elif state.isa[ValidationFailure]():
    print("Validation Failed at step", state[ValidationFailure].step)
```
