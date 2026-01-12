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
- [ ] **Read Proposal**: Thoroughly review `poc/typestate.md` to understand the architectural shift from Product Types to Sum Types (Typestate).
- [ ] **Verify Conventions**: Ensure alignment with `read`, `mut`, and `var` argument conventions as documented in `@docs/syntax/README.md`.

### Phase 2: Foundation
- [ ] **Data Structures**: Port `MockCertificate` and `ValidationStatus` from the original POC.
- [ ] **State Definitions**: Define `ValidationInProgress`, `ValidationSuccess`, and `ValidationFailure` structs.
- [ ] **State Wrapper**: Define the `ValidatorState` alias using `Variant`.

### Phase 3: Logic Implementation
- [ ] **Transition Function**: Implement `validate_step(var current: ValidationInProgress) -> ValidatorState`.
    - [ ] Handle Root Success/Failure/Expiry.
    - [ ] Handle Intermediate Success/Failure/Expiry.
    - [ ] Handle Not-a-CA and Subject/Issuer mismatch.
- [ ] **Refactor Dispatcher**: Adapt the compile-time `@parameter` dispatcher to work with the new state structs.

### Phase 4: Integration & Verification
- [ ] **Trace Generation**: Use `quint` to generate the required ITF traces from `specs/pki_path_validation.qnt`.
    - [ ] Generate `poc/valid.itf.json`
    - [ ] Generate `poc/untrusted.itf.json`
    - [ ] Generate `poc/mismatch.itf.json`
    - [ ] Generate `poc/expired.itf.json`
- [ ] **Harness Adaptation**: Update the ITF trace replay harness to handle `Variant` state checks.
- [ ] **Trace Execution**: Run `pixi run mojo poc/pki_validation_typestate.mojo` against:
    - [ ] `poc/valid.itf.json`
    - [ ] `poc/untrusted.itf.json`
    - [ ] `poc/mismatch.itf.json`
    - [ ] `poc/expired.itf.json`

## Notes & Issues
*Use this section to record any syntax hurdles, compiler errors, or limitations encountered with `Variant` or `var` conventions.*

- **Issue 1**: ...
- **Issue 2**: ...

## Technical Constraints
- Use `read` for immutable references.
- Use `mut` only for in-place modifications that do not change state.
- Use `var` and `^` for all state transitions.
- Strictly adhere to Mojo 24.5+ syntax.
