# Crypto Package

## Overview
`crypto/` is the pure‑Mojo cryptography layer that makes TLS 1.3 possible in
this repo. Each module exists because a specific TLS 1.3 step depends on it:
key schedule, key agreement, or record protection. Where possible, primitives
are tested against published vectors to ensure byte‑exact correctness.

## What Each Module Is For

### `crypto/bytes.mojo`
Utility helpers for hex parsing/formatting. This is the glue that lets tests
consume RFC vectors and compare outputs as hex strings.

### `crypto/sha256.mojo`
TLS 1.3 uses SHA‑256 for transcript hashing and as the hash function inside
HKDF. Without this, the key schedule can’t be reproduced correctly.

### `crypto/sha384.mojo`
Implements SHA‑384 for ECDSA‑SHA384 verification and handshake transcript
hashing when servers use SHA‑384 signatures. This is required for compatibility
with common ECDSA P‑256 certificates that are signed with SHA‑384.

### `crypto/hmac.mojo`
HKDF is built on HMAC. TLS 1.3 uses HMAC‑SHA256 as the core primitive to
extract and expand secrets.

### `crypto/hkdf.mojo`
Implements RFC 5869 HKDF (extract/expand). TLS 1.3 derives handshake and
application traffic keys with HKDF, so this is the backbone of the key schedule.

### `crypto/x25519.mojo`
Implements X25519 (RFC 7748) for ECDHE. TLS 1.3 uses X25519 to derive the
shared secret during the handshake.

### `crypto/aes_gcm.mojo`
Implements AES‑128 and GCM mode. TLS 1.3 record protection requires an AEAD;
AES‑GCM is the cipher suite for the current stage.

## Dependencies Between Modules
```
bytes.mojo  -> sha256.mojo
bytes.mojo  -> sha384.mojo
sha256.mojo -> hmac.mojo
hmac.mojo   -> hkdf.mojo
bytes.mojo  -> x25519.mojo
bytes.mojo  -> aes_gcm.mojo
```

## Testing

### Mojo Tests

Tests use RFC vectors to validate correctness:
- `tests/test_sha256.mojo`
- `tests/test_hmac.mojo`
- `tests/test_hkdf.mojo`
- `tests/test_x25519.mojo`
- `tests/test_aes_gcm.mojo`

SHA‑384 is currently exercised indirectly via TLS/X.509 verification paths
and should be added to vector tests when official vectors are wired in.

### Why Vectors Matter

Vector tests are fixed, published input/output pairs from standards. If any
vector fails, the implementation is wrong (padding, endianness, or algorithmic
errors). These are non‑negotiable for cryptography correctness.

### Commands

Run crypto tests:
```
pixi run test-crypto
```

Run TLS tests:
```
pixi run test-tls
```

Run HTTPS GET (real network) test:
```
pixi run test-https
```
