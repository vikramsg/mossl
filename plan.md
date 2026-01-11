# Implementation Plan: PKI Path Validation Spec

## Objective
Refactor the trivial `pki_chain.qnt` into a robust `pki_path_validation.qnt` model that formally specifies the rules for X.509 certificate chain verification as implemented in `src/pki/x509.mojo`.

## 1. Specification Design (`specs/pki_path_validation.qnt`)

### Entities to Model
- **Certificate**: A record containing `subject`, `issuer`, `is_root` (boolean), and a `public_key_id`.
- **Trust Store**: A set of certificates recognized as trusted roots.
- **Chain**: A sequence of certificates presented by the server.

### State Variables
- `current_chain`: The list of certificates being validated.
- `validation_status`: Enum (Pending, Valid, Invalid_Chain, Untrusted_Root, Subject_Issuer_Mismatch).

### Logical Rules (Actions)
- **`add_cert`**: Append a certificate to the current chain.
- **`validate_step`**: 
    - **Subject/Issuer**: Check if `current_chain[i].issuer == current_chain[i+1].subject`.
    - **Signature**: Check if `current_chain[i]` is signed by `current_chain[i+1]` (modeled by matching `public_key_id`).
    - **Basic Constraints**: Check if `current_chain[i+1]` has the `is_ca` flag set to true (preventing leaf-as-issuer attacks).
    - **Validity Period**: Check if `current_time` is between `not_before` and `not_after`.
- **`check_root`**: Verify if the last certificate in the chain is in the `TrustStore`.

### Completeness Analysis
To be truly "complete" (RFC 5280 compliant), the spec must eventually account for:
1. **Name Constraints**: Ensure a CA only issues for allowed subdomains.
2. **Policy Constraints**: Complex rules for certificate usage policies.
3. **Revocation**: CRL/OCSP status (not modeled in this phase).
4. **Path Length**: Restricting the maximum depth of the chain.

The initial refactor will focus on the **critical security quartet**: Subject/Issuer, Signatures, CA Flags, and Validity.

## 2. Mojo Trace Test (`tests/pki/test_pki_path_trace.mojo`)

- **Trace Loading**: Use `emberjson` to parse the ITF trace generated from the spec.
- **Mock Certificates**: Create a helper to generate mock `ParsedCertificate` objects that match the IDs in the trace.
- **Verification Loop**: 
    - Inject the mock chain into `verify_chain` in `x509.mojo`.
    - Assert that the Mojo implementation's step-by-step logic (or final result) matches the `validation_status` from the Quint trace.

## 3. Execution Steps
1.  **Draft Quint Spec**: Write the logic for path validation in `specs/pki_path_validation.qnt`.
2.  **Generate Traces**: Create both "Valid" and "Invalid" (adversarial) traces using `quint run`.
3.  **Update Trace Config**: Add the new spec and test path to `tests/trace_config.json`.
4.  **Implement Mojo Test**: Write the driver in `tests/pki/test_pki_path_trace.mojo`.
5.  **Verify**: Run `pixi run mojo tests/pki/test_pki_path_trace.mojo` and ensure it passes against the traces.
