# Plan: Universal HTTPS Certificate Support (RSA & P-384)

This document outlines the implementation plan to resolve all certificate verification failures in `docs/failing.md` by adding support for RSA and NIST P-384 signatures.

## Objective
Enable `HTTPSClient` to successfully connect to all major sites (Google, Wikipedia, GitHub, etc.) by implementing the missing cryptographic primitives required for their certificate chains.

## Evidence & Requirements
Analysis via `openssl s_client` confirms:
- **RSA Roots/Intermediates:** 100% of analyzed failing sites use RSA for their trust anchors.
- **P-384 Leaves:** Wikipedia, LetsEncrypt, and DigitalOcean use NIST P-384 leaf certificates.
- **Handshake Advertisement:** Sites like Microsoft and Apple reject our `ClientHello` because we do not advertise RSA support in the `signature_algorithms` extension.

## Implementation Steps

### 1. Multi-Precision BigInt (`pki/bigint.mojo`)
RSA requires 2048-bit or 4096-bit integer math, far exceeding the current 256-bit limit.
- **Spec**: `specs/bigint_pow.qnt` for modular exponentiation invariants.
- **Implementation**: Flexible `BigInt` struct with limb-based storage. Implement Montgomery multiplication for efficient $s^e \pmod n$ operations.
- **Verification**: Mojo trace test against Quint and vector tests for large prime modulus math.

### 2. RSA Verification (`pki/rsa.mojo`)
- **Spec**: `specs/crypto_rsa.qnt` for PKCS#1 v1.5 padding verification.
- **Implementation**: RSASSA-PKCS1-v1_5 verifier.
- **Integration**: Update `pki/x509.mojo` to recognize RSA OIDs and delegate to the new verifier.
- **Verification**: Test vectors from RFC 8017.

### 3. P-384 Elliptic Curve (`pki/ecdsa_p384.mojo`)
- **Spec**: `specs/crypto_p384.qnt` for curve arithmetic.
- **Implementation**: NIST P-384 curve parameters and point multiplication.
- **Verification**: NIST/RFC test vectors for P-384 signatures.

### 4. TLS Handshake Gating (`tls/tls13.mojo`)
- **Signature Algorithms**: Update `ClientHello` to include `rsa_pkcs1_sha256`, `rsa_pkcs1_sha384`, and `ecdsa_secp384r1_sha384`.
- **CertVerify**: Support processing RSA and P-384 `CertificateVerify` messages from the server.

## Acceptance Criteria
- `tests/test_https_get.mojo` passes for **all** sites listed in `docs/failing.md`, including:
    - `www.google.com` (RSA Leaf)
    - `www.wikipedia.org` (P-384 Leaf, RSA Root)
    - `www.github.com` (P-256 Leaf, RSA Root)
- No regression in existing P-256 sites (e.g., `example.com`).
