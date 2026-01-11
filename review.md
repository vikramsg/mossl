# PR Review: PKI Path Validation & TLS Specs

## Summary
This PR adds a new PKI path-validation spec/POC and a zero-copy ASN.1 parsing benchmark. However, there are **critical correctness issues** in the Quint specification, the test harness now has broken targets, and the Proof-of-Concept (PoC) is currently non-functional.

## 1. Critical Correctness: Unchecked Validity Dates
**Severity: High**

Both the specification (`specs/pki_path_validation.qnt`) and the Mojo implementation (`poc/pki_validation.mojo`) fail to enforce certificate validity periods (`not_before`, `not_after`).

*   **Spec:** The function `is_valid_at` is defined (L79) but **never called** in any transition action (`handle_root_success`, `handle_intermediate_success`, etc.).
*   **Mojo:** The `MockCertificate` struct does **not** include `not_before`/`not_after`, and `parse_cert_json` drops those fields from the trace entirely. The validator therefore cannot enforce validity dates.
*   **Impact:** The system will currently accept expired or not-yet-valid certificates as "Valid".

**Recommendation:**
Update `handle_root_success` and `handle_intermediate_success` in both Quint and Mojo to strictly assert `current_time >= cert.not_before and current_time <= cert.not_after`.

## 2. CI/Local Tests: Broken `test-specs` Target
**Severity: Blocker**

`pixi.toml` still references deleted specs (`specs/crypto_sha256.qnt`, `specs/crypto_hmac.qnt`, `specs/crypto_aead.qnt`, `specs/tls_http_gating.qnt`, `specs/pki_chain.qnt`). This will break `pixi run test-specs` and any `make test-all` gate.

**Recommendation:**
Update `pixi.toml` to remove references to deleted specs or use their successors (e.g., `specs/pki_path_validation.qnt`).

## 3. Spec Logic: "Angel" vs. "Gambler" Root Selection
**Severity: Medium**

The Quint spec uses non-deterministic choice (`nondet root = matching_roots.oneOf()`) to pick a trust anchor.

*   **The Flaw:** If `trust_store` contains two roots with the same Subject (e.g., an old cross-signed root and a new one), and the spec picks the "wrong" one (key mismatch), it transitions to `Signature_Failure` instead of trying the other one.
*   **Reality:** Real implementations (and your Mojo loop) iterate through *all* candidates to find *any* valid path.
*   **Fix:** The invariant `ValidImpliesTrustedRoot` is safe, but the transition logic `handle_root_success` should be predicated on `matching_roots.exists(...)` rather than picking one and testing it.

## 4. Spec Consistency: `Not_A_CA` Unreachable Under Invariant
**Severity: Medium**

The invariant `IntermediatesMustBeCA` makes any state with a non-CA intermediate illegal, which means the `Not_A_CA` failure transition can never be explored or validated in the spec. This contradicts the presence of `Not_A_CA` as an intended failure status.

**Recommendation:**
Drop `IntermediatesMustBeCA` so `Not_A_CA` remains a reachable failure path during validation.
