# Crypto Package (Stage 1)

## Overview
The `crypto/` directory contains pure Mojo implementations of the Stage 1
cryptographic primitives required for TLS 1.3 key scheduling:
- SHA-256
- HMAC-SHA256
- HKDF (RFC 5869)

These are implemented without external language bindings and validated with
RFC test vectors.

## Modules
- `crypto/bytes.mojo`
  - Hex parsing and formatting helpers for test vectors.
- `crypto/sha256.mojo`
  - SHA-256 implementation with padding and compression.
- `crypto/hmac.mojo`
  - HMAC-SHA256 built on `crypto/sha256.mojo`.
- `crypto/hkdf.mojo`
  - HKDF extract/expand built on `crypto/hmac.mojo`.

## Data Flow
```
bytes.mojo  -> sha256.mojo
sha256.mojo -> hmac.mojo
hmac.mojo   -> hkdf.mojo
```

## Tests
Mojo tests live under `tests/` and use RFC vectors:
- `tests/test_sha256.mojo`
- `tests/test_hmac.mojo`
- `tests/test_hkdf.mojo`

Run all Stage 1 tests:
```
pixi run test-stage1
```

Run all Stage 1 Quint specs:
```
pixi run test-specs
```
