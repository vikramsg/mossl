# HTTPS GET Enablement Spec (Mojo-Native TLS Plan)

## Roadmap for `MojoTLS` (Secure MVP, Native Implementation)

### Stage 0: Protocol Skeleton (Abstract Crypto)
- **Handshake State Machine**:
    1. Send `ClientHello` (KeyShare, SupportedGroups, SignatureAlgorithms).
    2. Receive `ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`.
    3. Verify Certificate and Signature (abstract gate).
    4. Send `Finished`.
- **Record Protocol Gating**: Application data only after handshake completion.
- **Specs + Tests**: Add Quint spec tests that enforce transition legality and gating; add Mojo tests that validate message sequencing against the same constraints.

### Stage 1: Hash/MAC/KDF (TLS 1.3 Key Schedule)
- **Hashing**: SHA-256 (SHA-384 optional for later).
- **MAC**: HMAC-SHA256.
- **Key Derivation**: HKDF per RFC 5869.
- **Specs + Tests**: Quint spec covers KDF contracts; Mojo tests use RFC 5869 vectors.

### Stage 2: Key Exchange
- **Key Exchange**: X25519 for ECDHE.
- **BigInt Library**: Minimal BigInt support as required for curve operations.
- **Specs + Tests**: Quint spec asserts `DH(skA, pkB) == DH(skB, pkA)`; Mojo tests include known vectors.

### Stage 3: Record Layer AEAD
- **AEAD**: AES-GCM-128 for TLS 1.3.
- **Nonce/Sequence Handling**: Per-record nonce derivation and strict sequence progression.
- **Specs + Tests**: Quint spec enforces integrity (modified tag fails); Mojo tests flip bits and assert decrypt failure.

### Stage 4: Certificates and Signatures
- **ASN.1 Decoder**: Parse DER.
- **X.509 Parser**: Extract public keys and extensions.
- **Signature Verification**: ECDSA P-256 (add RSA later if needed).
- **Trust Store**: Load system CA bundle, verify chain and hostname.
- **Specs + Tests**: Quint spec requires valid chain and hostname before handshake completes; Mojo tests validate known-good and known-bad cert chains.

### Stage 5: `lightbug_http` Integration
- Create a `TLSSocket` wrapper that conforms to the interface expected by `lightbug_http.client.Client`.
- Implement `connect_https` to perform the handshake before returning the encrypted stream.
- **Specs + Tests**: Quint spec ensures no HTTP I/O before `HandshakeComplete`; Mojo tests hit `https://httpbin.org/get`.

### Stage Requirements (All Stages)
- **Every stage must include matching Quint spec tests and Mojo tests** that cover the same contract (one spec test maps to one Mojo test case or vector set).

## Technical Architecture

```
HTTPRequest
  |
  v
lightbug_http Client
  |
  v
TLSSocket Wrapper
  |\
  | \-> TLS Record Layer -> MojoCrypto (AES-GCM-128)
  |
  \--> TLS Handshake Engine -> MojoCrypto (X25519, ECDSA P-256)
                         \
                          -> MojoPKI (ASN.1, X.509, Trust Store)
  |
  v
TCP Socket
```

## Implementation and Test Guidance

### Code Layout
- **Mojo implementation** lives under `src/` (e.g., `src/tls/`, `src/crypto/`, `src/pki/`).
- **Mojo tests** live under `tests/` and are named to match the stage (e.g., `tests/hkdf_test.mojo`).
- **Quint specs** live under `specs/` and include stage-specific tests.

### Stage Gate (Spec + Mojo Tests)
- Every stage adds or updates **both**:
  - a Quint spec test in `specs/`
  - a Mojo test in `tests/`
- The Mojo test should exercise the same contract as the spec test (one-to-one or vector set).
- **Advancing to the next stage requires all tests up to and including the current stage to pass.**
- **After completing a stage and passing tests, create a git commit for that stage.**

### Stage Checklist

| Stage | Spec tests added | Mojo tests added | All tests up to stage pass |
| --- | --- | --- | --- |
| Stage 0: Protocol Skeleton | [ ] | [ ] | [ ] |
| Stage 1: Hash/MAC/KDF | [ ] | [ ] | [ ] |
| Stage 2: Key Exchange | [ ] | [ ] | [ ] |
| Stage 3: Record Layer AEAD | [ ] | [ ] | [ ] |
| Stage 4: Certificates and Signatures | [ ] | [ ] | [ ] |
| Stage 5: lightbug_http Integration | [ ] | [ ] | [ ] |

### Running Tests
- Quint: `npx quint test specs/<spec>.qnt`
- Mojo: `pixi run <test-command>` (define stage-specific commands in `pixi.toml`)
