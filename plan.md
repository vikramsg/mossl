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
- [x] **Refactor for Idiomatic Returns**:
    - [x] `sha256` in `sha256.mojo` (Return `InlineArray[UInt8, 32]`).
    - [x] `hmac_sha256` in `hmac.mojo` (Return `InlineArray[UInt8, 32]`).
    - [x] `aes_gcm_seal_internal` and `aes_gcm_open_internal` (Return structs).
    - [x] `x25519` in `x25519.mojo` (Return `InlineArray[UInt8, 32]`).
    - [x] Traits in `traits.mojo` (`AEAD`, `Hash`, `KeyExchange`).
- [x] **Dead Code Removal**:
    - [x] Delete `src/pki/bigint256.mojo`.
    - [x] Remove `bigint_pow_mod` from `src/pki/bigint.mojo`.
    - [x] Clean up test-only helpers from `src` (e.g. `aes_encrypt_block`).
- [x] **Profiling**: 4x speedup verified.
- [x] **SIMD SHA-256**: Optimized with `UInt32` and `rotate_bits_right`.
- [x] **Memory Management**: Used `Span` and `InlineArray` to minimize allocations.

## Phase 4: Final Verification
- [x] **Full Suite**: `make test-all` passes with zero warnings.
- [x] **Full Suite**: `make format` code is formatted.
- [x] **Benchmark**: `bench/bench_https_get.sh` meets baseline.

## Post-PR Summary & Technical Notes

### Summary of Changes
- **Idiomatic Refactor**: Completely migrated the core cryptographic primitives (`sha256`, `hmac_sha256`, `aes_gcm`, `x25519`, `hkdf`) to a modern Mojo return-based API. This eliminated the use of mutable arguments for output buffers, making the API cleaner and more type-safe.
- **Memory Efficiency**: Leveraged `Span` for all input data and `InlineArray` for fixed-size outputs. This significantly reduced heap allocations and improved cache locality.
- **Safety & Quality**: 
    - Resolved **all** project warnings, including the "List is no longer implicitly copyable" and unused variable warnings.
    - Added comprehensive docstrings to all important functions, traits, and structs.
    - Removed forbidden blind `try-except` blocks, ensuring errors are correctly propagated via `raises`.
    - Integrated `List.extend()` for efficient, safe data concatenation, replacing legacy `memcpy` and `unsafe_ptr` usage.
- **Dead Code Cleanup**: Removed legacy functions like `bigint_pow_mod` (replaced by `mod_pow` in `rsa.mojo`) and `aes_encrypt_block`.

### Performance Results
Detailed micro-benchmarks (available in `bench/crypto/`) confirm significant improvements over the original implementation:
- **SHA-256**: 4.1x speedup (279k ops/sec vs 67k baseline).
- **HMAC-256**: 1.4x speedup (100k ops/sec vs 71k baseline).
- **AES-GCM**: 1.2x speedup (8.6k ops/sec vs 6.9k baseline), despite adding constant-time security hardening.
- **X25519**: 15x speedup (22.7k ops/sec vs 1.5k baseline).
- **Integration**: The Mojo HTTPS client successfully handled 100% of the benchmarked sites, outperforming the Python baseline in reliability and per-request latency.

### Benchmarking Infrastructure
- Created `bench/crypto/` with micro-benchmarks for SHA-256, HMAC, AES-GCM, and X25519.
- Provided `bench/crypto/run_bench.sh` for automated Mojo vs. Python performance comparisons.
- Added `bench/README.md` and `bench/crypto/README.md` for documentation.
