# Implementation Plan: Cryptography Modernization

This plan outlines the steps required to implement the roadmap defined in `docs/future/crypto.md`.

**Note**: 
1. After completing each phase, you must run `make format && make test-all` to ensure code quality and project-wide correctness.
2. Each new test should be added to pixi.toml, otherwise `make test-all` will not run it.

## Phase 1: Testing Infrastructure & Correctness
Establish the differential testing framework to ensure that any future optimizations or security changes do not break correctness.

- [ ] **Python Interop Harness**: Create a base testing utility in `tests/crypto/` that handles byte conversion between Mojo and Python (`cryptography` library).
- [ ] **SHA-256 Differential Test**:
    - [ ] Implement randomized test with 1,000+ iterations comparing `sha256_bytes` with `hashlib.sha256`.
- [ ] **AES-GCM Differential Test**:
    - [ ] Implement randomized test with 1,000+ iterations comparing `aes_gcm_seal/open` with `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
    - [ ] Add "Round-Trip" validation (Mojo Encrypt -> Python Decrypt and vice-versa).
- [ ] **X25519 Differential Test**:
    - [ ] Implement randomized test for public key generation and shared secret computation against `cryptography.hazmat.primitives.asymmetric.x25519`.
- [ ] **Wycheproof Integration**: Add support for loading and running Project Wycheproof test vectors via Python interop.

## Phase 2: Security Hardening (Constant-Time)
Address side-channel vulnerabilities by removing secret-dependent branching and memory access.

- [ ] **Constant-Time Utilities**:
    - [ ] Implement `constant_time_compare` in `src/crypto/bytes.mojo`.
    - [ ] Implement bitwise conditional move/swap helpers.
- [ ] **AES-GCM Hardening**:
    - [ ] Replace `if input_tag_u128 != calculated_tag_u128` with `constant_time_compare`.
    - [ ] **Critical**: Implement bit-sliced AES or a table-less approach to eliminate cache-timing leaks from S-Box lookups.
- [ ] **X25519 Hardening**:
    - [ ] Replace Montgomery ladder branching (`if swap == 1`) with a constant-time conditional swap (CSWAP).
    - [ ] Audit field arithmetic (`fe_ge_p`, etc.) to remove all secret-dependent branches.
- [ ] **CSPRNG**:
    - [ ] Replace the deterministic `random_bytes` in `src/tls/tls13.mojo` with a secure wrapper around `/dev/urandom`.
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