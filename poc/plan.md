# POC Plan: PKI Path Validation Prototype (Declarative Arch)

## Objective
Implement a production-quality prototype of the PKI path validation state machine, mirroring the declarative Quint specification and utilizing Mojo's metaprogramming for an "automatic" dispatcher.

## 1. Design & Patterns
- **Comptime Enums**: Use a struct with `alias` members (standard pattern in 0.25.6, equivalent to `comptime` in 0.26+) to represent `ValidationStatus`.
- **Atomic Actions**: Each Quint action (e.g., `handle_root_success`) will be implemented as a standalone method.
- **Metaprogramming Dispatcher**: Instead of a manual `if/else` chain, `validate_step` will iterate over a list of available actions at compile-time using `@parameter`.
- **Trace Replay Harness**: Automated verification by replaying ITF JSON traces generated from the Quint spec.

## 2. Implementation Steps
- [ ] **Step 1: Status Enum**
    - Define `ValidationStatus` with codes for: `PENDING`, `VALID`, `UNTRUSTED_ROOT`, `SUBJECT_ISSUER_MISMATCH`, `SIGNATURE_FAILURE`, `NOT_A_CA`.
- [ ] **Step 2: Certificate Metadata**
    - Define `MockCertificate` with SKID/AKID support.
- [ ] **Step 3: Action Implementation**
    - Implement each of the 8 atomic actions from the Quint spec.
- [ ] **Step 4: The Dispatcher**
    - Implement `validate_step` using a compile-time loop over a list of action method pointers (or similar specialized dispatch).
- [ ] **Step 5: Trace Harness**
    - Implement ITF parsing and state-by-state assertion.

## 3. Verification Checklist
- [ ] `test_valid_chain` replay: PASSED.
- [ ] `test_untrusted_root` replay: PASSED.
- [ ] `test_mismatch_issuer` replay: PASSED.
- [ ] `test_not_a_ca` logic: PASSED.

## Notes on Comptime
- In Mojo 0.25.6.1, the `comptime` keyword for declarations is not yet fully available (it's in the 0.26+ nightlies found in `/tmp/mojo`). We use `alias` which provides the same compile-time behavior in this version.
- **Dispatcher Logic**: By using a list of actions and returning early on the first match, we perfectly replicate the non-deterministic `any` block behavior of Quint in a deterministic, prioritized Mojo implementation.

## Execution Results
- TBD
