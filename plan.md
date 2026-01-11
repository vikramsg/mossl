# Implementation Plan: Cryptography Modernization

This plan outlines the steps required to implement the roadmap defined in `docs/future/crypto.md` and address non-idiomatic patterns.

**Note**: 
1. After completing each phase, run `make format && make test-all` to ensure code quality and project-wide correctness.
2. Performance Mandate: Implementation must be faster or equal to the original.
3. Idiomatic Mojo: **CRITICAL**: No `mut` arguments for results. Use returns (structs/traits) instead.
4. Zero Warnings: All compiler warnings must be resolved.

## Phase 1: Testing Infrastructure & Correctness
- [x] **Python Interop Harness**: Base testing utility in `tests/crypto/`.
- [x] **SHA-256 Differential Test**: Randomized test (1,000+ iterations).
- [x] **AES-GCM Differential Test**: Randomized test (1,000+ iterations) + Round-Trip.
- [x] **X25519 Differential Test**: Randomized test for key exchange.
- [x] **Wycheproof Integration**:
    - [x] X25519 runner (Passed).
    - [x] HMAC-SHA256 runner (Passed).
    - [x] AES-GCM runner (Passed).
    - [x] SHA-256 validation (Verified via HMAC).

## Phase 2: Security Hardening (Constant-Time)
- [x] **Constant-Time Utilities**: `constant_time_compare`, `ct_select`, `ct_swap`.
- [x] **AES-GCM Hardening**:
    - [x] Replace tag check with `constant_time_compare`.
    - [x] **Vectorized S-Box**: Implemented $O(16)$ constant-time lookup using SIMD.
- [x] **X25519 Hardening**:
    - [x] Constant-time Montgomery ladder (CSWAP).
- [x] **CSPRNG**: Pure Mojo `/dev/urandom` implementation.
- [x] **Zeroization**: `zeroize()` calls for sensitive material.

## Phase 3: Idiomatic Refactor & Performance
- [ ] **Refactor for Idiomatic Returns**:
    - [ ] `sha256` in `sha256.mojo` (Return `InlineArray[UInt8, 32]`).
    - [ ] `hmac_sha256` in `hmac.mojo` (Return `InlineArray[UInt8, 32]`).
    - [ ] `aes_gcm_seal_internal` and `aes_gcm_open_internal` (Return structs).
    - [ ] `x25519` in `x25519.mojo` (Return `InlineArray[UInt8, 32]`).
    - [ ] Traits in `traits.mojo` (`AEAD`, `Hash`, `KeyExchange`).
- [ ] **Dead Code Removal**:
    - [ ] Delete `src/pki/bigint256.mojo`.
    - [ ] Remove `bigint_pow_mod` from `src/pki/bigint.mojo`.
    - [ ] Clean up test-only helpers from `src` (e.g. `aes_encrypt_block`).
- [x] **Profiling**: 4x speedup verified.
- [x] **SIMD SHA-256**: Optimized with `UInt32` and `rotate_bits_right`.
- [x] **Memory Management**: Used `Span` and `InlineArray` to minimize allocations.

## Phase 4: Final Verification
- [ ] **Full Suite**: `make test-all` passes with zero warnings.
- [ ] **Full Suite**: `make format` code is formatted.
- [ ] **Benchmark**: `bench/bench_https_get.sh` meets baseline.