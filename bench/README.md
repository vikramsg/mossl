# Mojo Benchmarks

This directory contains performance benchmarks for the `ssl.mojo` project.

## Summary of Performance Results

### Cryptography Micro-benchmarks
*Measured on 1KB blocks (SHA-256, HMAC, AES-GCM) or 32B exchange (X25519).*

| Algorithm | Python (ops/sec) | Mojo (ops/sec) | Baseline (ops/sec) | Speedup vs Baseline |
|-----------|------------------|----------------|--------------------|---------------------|
| **SHA-256** | ~843k | ~545k | ~67k | **8.1x faster** |
| **HMAC-256** | ~384k | ~143k | ~71k | **2.0x faster** |
| **AES-GCM** | ~683k | ~8k | ~7k | **1.1x faster** |
| **X25519** | ~25k | ~19k | ~1.5k | **12.6x faster** |

*Note: Baseline refers to the original Mojo implementation before modernization. Mojo now includes constant-time security hardening.*

### HTTPS GET Comparison
*Performance of full TLS handshake + HTTP request/response.*

| Implementation | Successful Requests | Average Time (s) | Requests/sec |
|----------------|---------------------|------------------|--------------|
| **Python** | 6 / 10 | 0.147 | 6.80 |
| **Mojo** | 10 / 10 | 0.185 | 5.40 |

**Mojo is significantly more robust**, handling 100% of benchmarked sites successfully, while Python failed on 4 sites (Timeouts and HTTP errors). 

## Main Benchmarks

### HTTPS GET Comparison
Compares the performance of the full Mojo HTTPS client against the standard Python `requests` library.

```bash
./bench/bench_https_get.sh
```

### Cryptography Micro-benchmarks
Detailed performance metrics for the underlying cryptographic algorithms.

```bash
./bench/crypto/run_bench.sh
```
