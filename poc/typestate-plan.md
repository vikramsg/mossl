# Plan: Typestate Implementation for PKI Validation

This plan outlines the steps to implement a safe, typestate-based version of the PKI validation logic, mirroring the Quint specification in `specs/pki_path_validation.qnt`.

## Acceptance Criteria
- [ ] A new Mojo script `poc/pki_validation_typestate.mojo` is created.
- [ ] The script uses `utils.Variant` to represent the validator's state.
- [ ] State transitions use the `var` (ownership transfer) convention with the `^` operator.
- [ ] The script passes the same ITF trace tests as the original `poc/pki_validation.mojo`.
- [ ] No invalid states (e.g., `ValidationSuccess` with an incomplete step count) are representable.

## Checklist

### Phase 1: Research & Understanding
- [x] **Read Proposal**: Thoroughly review `poc/typestate.md` to understand the architectural shift from Product Types to Sum Types (Typestate).
- [x] **Verify Conventions**: Ensure alignment with `read`, `mut`, and `var` argument conventions as documented in `@docs/syntax/README.md`.

### Phase 2: Foundation
- [x] **Data Structures**: Port `MockCertificate` and `ValidationStatus` from the original POC.
- [x] **State Definitions**: Define `ValidationInProgress`, `ValidationSuccess`, and `ValidationFailure` structs.
- [x] **State Wrapper**: Define the `ValidatorState` alias using `Variant`.

### Phase 3: Logic Implementation
- [x] **Transition Function**: Implement `validate_step(var current: ValidationInProgress) -> ValidatorState`.
    - [x] Handle Root Success/Failure/Expiry.
    - [x] Handle Intermediate Success/Failure/Expiry.
    - [x] Handle Not-a-CA and Subject/Issuer mismatch.
- [x] **Refactor Dispatcher**: Adapt the compile-time `@parameter` dispatcher to work with the new state structs.

### Phase 4: Integration & Verification
- [x] **Trace Generation**: Use `quint` to generate the required ITF traces from `specs/pki_path_validation.qnt`.
    - [x] Generate `poc/valid.itf.json`
    - [x] Generate `poc/untrusted.itf.json`
    - [x] Generate `poc/mismatch.itf.json`
    - [x] Generate `poc/expired.itf.json`
- [x] **Harness Adaptation**: Update the ITF trace replay harness to handle `Variant` state checks.
- [x] **Trace Execution**: Run `pixi run mojo poc/pki_validation_typestate.mojo` against:
    - [x] `poc/valid.itf.json`
    - [x] `poc/untrusted.itf.json`
    - [x] `poc/mismatch.itf.json`
    - [x] `poc/expired.itf.json`

## Notes & Issues
- **Issue 1**: `Variant` requires its types to be both `Movable` and `Copyable`. For types containing `List`, this requires implementing `__copyinit__` (e.g., using `self.chain = other.chain.copy()`) and `__moveinit__` (using `deinit other`).
- **Issue 2**: `Optional.value()` may return a reference depending on context. To move a value out of an `Optional`, use `maybe_next.take()`.
- **Issue 3**: The modern `__moveinit__` syntax requires `deinit other: Self` to signal destruction of the source.
- **Issue 4**: `Variant` operations (like `unsafe_take`) require the instance to be mutable.
- **Issue 5**: Ownership transfer (`^`) can only be used on values with a clear "origin" (e.g., local variables). Function results that are already owned often don't need `^` or can't use it if they are temporaries.

## Technical Constraints
- Use `read` for immutable references.
- Use `mut` only for in-place modifications that do not change state.
- Use `var` and `^` for all state transitions.
- Strictly adhere to Mojo 24.5+ syntax.
