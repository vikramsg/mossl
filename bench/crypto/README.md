# Cryptography Micro-benchmarks

This directory contains micro-benchmarks for the core cryptographic primitives in `ssl.mojo`.

## Benchmarks

- **SHA-256**: Measures hashing performance for 1KB blocks.
- **HMAC-SHA256**: Measures authentication performance for 1KB blocks.
- **AES-GCM**: Measures combined seal and open performance for 1KB blocks.
- **X25519**: Measures key exchange performance (32-byte scalars).

## Running the Benchmark

To run both the Mojo and Python versions for comparison:

```bash
./bench/crypto/run_bench.sh
```

## Significance

These benchmarks are used to verify the performance gains achieved through the use of idiomatic Mojo patterns like `InlineArray`, `Span`, and return-based APIs.
