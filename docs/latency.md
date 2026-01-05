# Cryptographic Latency Analysis

This document provides a detailed breakdown of the latency for various cryptographic and PKI operations in `ssl.mojo`. Measurements were taken using Mojo's standard `benchmark` library with `-O3` optimization on Jan 5, 2026.

## Latency Summary (Per-Operation)

| Operation | Mean Latency | Metric |
| :--- | :--- | :--- |
| **Trust Store Load (148 certs)** | **1.36 ms** | Handshake Setup |
| **ECDSA P-256 Verify** | **0.33 ms** | Handshake Auth |
| **AES-GCM Seal (16 bytes)** | **26.75 µs** | Small Record Latency |
| **AES-GCM Seal (16 KB)** | **220.21 µs** | Large Record Latency |
| **AES Context Init** | **1.37 µs** | Per-Key Setup |
| **GHASH Table Init** | **27.48 µs** | **Per-Record Overhead** |

## Analysis of Bottlenecks

### 1. Handshake Components
Handshake latency is dominated by network round-trips, as the CPU costs for local processing are now minimal:
- **Trust Store Loading**: At **1.36 ms**, parsing the system root store is fast but could be cached to save time across multiple connections.
- **Signature Verification**: ECDSA P-256 verification at **0.33 ms** is highly optimized. A typical handshake involving 3 certificate checks and 1 `CertificateVerify` adds only ~1.3 ms of CPU time.

### 2. AES-GCM Per-Record Overhead
The benchmark reveals a significant architectural bottleneck in the current AES-GCM implementation:
- **Initialization Cost**: Every call to `aes_gcm_seal` or `aes_gcm_open` currently re-initializes the entire context.
- **GHASH Precomputation**: Initializing the 64KB Comb table for GHASH takes **27.48 µs**. 
- **Impact on Small Records**: For a 16-byte record, the total latency is **26.75 µs** (The `benchmark` mean for the seal operation is consistent with the init cost, indicating init is nearly 100% of the cost for tiny records).
- **Impact on Throughput**: This fixed overhead limits throughput for small payloads. Even without processing any data, we are capped at ~36,000 records per second per core due to this initialization.

## Recommendations

### Short-Term: Context Caching
The most impactful latency optimization is to refactor the AES-GCM API to separate **Initialization** from **Processing**.
- Pre-compute the `AESContextInline` and `GHASHContextInline` once per session key.
- Refactor `aes_gcm_seal` to accept these pre-computed contexts.
- Expected improvement: **~90% reduction** in latency for small TLS records (from 27µs to ~2µs).

### Long-Term: Connection Reuse
Since individual CPU operations are now in the sub-millisecond range, the ~100-500ms of "real" time observed in HTTPS tests is entirely network-bound. Implementing TLS Session Resumption or persistent connections (Keep-Alive) will have a much larger impact on perceived performance than further CPU optimizations.

## Benchmark Methodology
Benchmarks were executed using:
```bash
pixi run mojo run -O3 -I src bench/v2/latency_benchmark.mojo
```
The `benchmark` module provides warmup iterations and statistical averaging (Mean of N iterations) to ensure stable results.
