# Implementation Plan: Cryptography Modernization

This plan outlines the steps required to implement the roadmap defined in `docs/future/crypto.md`.

**Note**: 
1. After completing each phase, you must run `make format && make test-all` to ensure code quality and project-wide correctness.
2. Each new test should be added to pixi.toml, otherwise `make test-all` will not run it.
3. Functional correctness (Phase 1) includes both positive validation (matching output) and negative validation (rejecting invalid inputs).

## Phase 1: Testing Infrastructure & Correctness
Establish the differential testing framework to ensure that any future optimizations or security changes do not break correctness.

- [x] **Python Interop Harness**: Create a base testing utility in `tests/crypto/` that handles byte conversion between Mojo and Python (`cryptography` library).
- [x] **SHA-256 Differential Test**:
    - [x] Implement randomized test with 1,000+ iterations comparing `sha256_bytes` with `hashlib.sha256`.
- [x] **AES-GCM Differential Test**:
    - [x] Implement randomized test with 1,000+ iterations comparing `aes_gcm_seal/open` with `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
    - [x] Add "Round-Trip" validation (Mojo Encrypt -> Python Decrypt and vice-versa).
- [x] **X25519 Differential Test**:
    - [x] Implement randomized test for public key generation and shared secret computation against `cryptography.hazmat.primitives.asymmetric.x25519`.
- [x] **Wycheproof Integration**:
    - [x] X25519 runner: Verify scalar multiplication against Wycheproof vectors (Passed).
    - [x] HMAC-SHA256 runner: Verify integrity check and tag truncation (Passed).
    - [x] AES-GCM runner:
        - [x] Fix: Reject zero-length IV (Wycheproof Tests 311, 312) - FIXED.
        - [x] Add explicit code comments in `src/crypto/aes_gcm.mojo` explaining the rejection of zero-length IVs per NIST SP 800-38D - FIXED.
    - [x] SHA-256 validation: Verified via HMAC-SHA256 Wycheproof runner (Passed).

## Phase 2: Security Hardening (Constant-Time)
Address side-channel vulnerabilities by removing secret-dependent branching and memory access.

- [x] **Constant-Time Utilities**:
    - [x] Implement `constant_time_compare` in `src/crypto/bytes.mojo`.
    - [x] Implement bitwise conditional move/swap helpers.
- [ ] **AES-GCM Hardening**:
    - [x] Replace `if input_tag_u128 != calculated_tag_u128` with `constant_time_compare`.
    - [ ] **Critical**: Implement bit-sliced AES or a table-less approach to eliminate cache-timing leaks from S-Box lookups.
- [ ] **X25519 Hardening**:
    - [x] Replace Montgomery ladder branching (`if swap == 1`) with a constant-time conditional swap (CSWAP).
    - [ ] Audit field arithmetic (`fe_ge_p`, etc.) to remove all secret-dependent branches.
- [x] **CSPRNG**:
    - [x] Replace the deterministic `random_bytes` in `src/tls/tls13.mojo` with a secure wrapper around `/dev/urandom`.
- [ ] **Zeroization**:
    - [ ] Add `zeroize()` calls to clear keys and ephemeral secrets from memory after use.

### Phase 2 Verification (Side-Channel Testing)
Standard functional tests cannot detect timing leaks. These specialized tests are required:
- [ ] **Statistical Timing Analysis (dudect)**:
    - [ ] Implement a `dudect` style test harness that runs primitives with fixed vs. random inputs and uses Welch's t-test to detect timing differences.
- [ ] **Secret-Dependent Branch Detection**:
    - [ ] Use a tool (or manual assembly audit) to ensure that the compiler has not introduced conditional branches in the "hardened" paths.
- [ ] **Negative Differential Testing**:
    - [ ] Test with incorrect tags, corrupted ciphertexts, and invalid X25519 points to ensure that error paths are also constant-time.

## Phase 3: Performance Optimization
Leverage Mojo's unique features to improve throughput while maintaining security.

- [ ] **SIMD SHA-256**:
    - [ ] Vectorize the SHA-256 message schedule ($\sigma$ functions) using Mojo `SIMD` types.
- [ ] **SIMD AES**:
    - [ ] Optimize the record layer by using SIMD for block XORs and parallel processing of multiple blocks where possible.
- [ ] **Memory Management**:
    - [ ] Reduce `List[UInt8]` to `Bytes` or `InlineArray` conversions in hot paths.
    - [ ] Use `Span` and `InPlace` operations to minimize heap allocations.
