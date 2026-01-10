# Wycheproof Test Vectors

The test vectors in this directory are obtained from the [Google Wycheproof](https://github.com/google/wycheproof) project. 

Wycheproof provides a collection of unit tests that check for known vulnerabilities and edge cases in cryptographic implementations.

## How these files were obtained

The files were retrieved by cloning the repository and copying the relevant JSON files from the `testvectors_v1` directory:

```bash
git clone --depth 1 https://github.com/google/wycheproof /tmp/wycheproof
cp /tmp/wycheproof/testvectors_v1/aes_gcm_test.json tests/fixtures/wycheproof/
cp /tmp/wycheproof/testvectors_v1/hmac_sha256_test.json tests/fixtures/wycheproof/
cp /tmp/wycheproof/testvectors_v1/x25519_test.json tests/fixtures/wycheproof/
```

## Included Files

- `aes_gcm_test.json`: Vectors for AES-GCM (Authenticated Encryption with Associated Data).
- `hmac_sha256_test.json`: Vectors for HMAC-SHA256 (Hash-based Message Authentication Code).
- `x25519_test.json`: Vectors for X25519 (Elliptic Curve Diffie-Hellman key exchange).

Note: Standalone SHA-256 testing is currently covered indirectly via the HMAC-SHA256 vectors.
