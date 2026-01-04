# HTTPS GET Enablement Spec (Mojo-Native TLS Plan)

**PURE MOJO ONLY**: All implementations must be in Mojo; no Python or external language bindings.

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
- **Specs + Tests**: Quint spec defines generic KDF contracts (determinism, length sensitivity, domain separation); Mojo tests use RFC 5869 vectors.

### Stage 2: Key Exchange
- **Key Exchange**: X25519 for ECDHE.
 - **BigInt Library**: Not required for X25519 (fixed-limb implementation). Defer minimal BigInt to the stage that introduces curves or algorithms that need arbitrary-precision math.
- **Specs + Tests**: Quint spec defines generic shared-secret agreement; Mojo tests include known vectors.

### Stage 3: Record Layer AEAD
- **AEAD**: AES-GCM-128 for TLS 1.3.
- **Nonce/Sequence Handling**: Per-record nonce derivation and strict sequence progression.
- **Specs + Tests**: Quint spec defines generic AEAD integrity contracts; Mojo tests use known AES-GCM vectors.

### Stage 4: Certificates and Signatures
- **ASN.1 Decoder**: Parse DER.
- **X.509 Parser**: Extract public keys and extensions.
- **Signature Verification**: ECDSA P-256 (add RSA later if needed).
- **BigInt Library**: Minimal BigInt support for ECDSA P-256 field arithmetic (or equivalent fixed-limb field implementation).
- **Trust Store**: Load system CA bundle, verify chain and hostname.
- **Specs + Tests**: Quint specs define generic signature and chain gating; Mojo tests validate known-good and known-bad chains.

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
- **Mojo implementation** lives under `crypto/` for Stage 1; later stages will add `tls/` and `pki/` at repo root.
- **Mojo tests** live under `tests/` and use `test_*` naming (e.g., `tests/test_hkdf.mojo`).
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
| Stage 0: Protocol Skeleton | [x] | [x] | [x] |
| Stage 1: Hash/MAC/KDF | [x] | [x] | [x] |
| Stage 2: Key Exchange | [x] | [x] | [x] |
| Stage 3: Record Layer AEAD | [x] | [x] | [x] |
| Stage 4: Certificates and Signatures | [x] | [x] | [x] |
| Stage 5: lightbug_http Integration | [x] | [x] | [x] |

### Running Tests
- Quint: `npx quint test specs/<spec>.qnt`
- Mojo: `mojo run -I . tests/test_<name>.mojo` or `pixi run test-stage1` for the grouped Stage 1 commands
