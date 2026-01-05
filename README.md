# mossl

## Goal
Implement a **pure Mojo** TLS 1.3 client stack sufficient to perform HTTPS GETs via `lightbug_http`.

## Status
- TLS 1.3 MVP client implemented with **real HTTPS GET** support.
- Supported features:
    - Cipher suite: `TLS_AES_128_GCM_SHA256`.
    - Key exchange: `X25519`.
    - Signature algorithms: `ECDSA P-256` (SHA-256), `ECDSA P-384` (SHA-384), `RSA-PSS` (SHA-256), `RSA-PKCS1` (SHA-256/SHA-384).
    - Certificate verification: Full chain validation using system trust store (or provided CA bundle).
- Current limits: No ALPN, no session resumption, single cipher suite.

## Layout
```
src/
  crypto/        Stage 1 crypto primitives (pure Mojo)
  pki/           PKI implementation
  tls/           TLS implementation
docs/            Roadmap and specs
specs/           Quint specs
tests/           Mojo tests (test_*.mojo)
scripts/         Usage scripts
```

## TLS HTTPS Architecture
```
lightbug_http
  |
  v
tls/https_client.mojo   (adapter: read/write/close for lightbug_http)
  |
  v
tls/connect_https.mojo  (TCP connect + TLS handshake)
  |
  v
tls/tls_socket.mojo     (handshake gating + app data I/O)
  |
  v
tls/tls13.mojo          (TLS 1.3 client: records, key schedule, cert verify)
  |            \
  |             \--> crypto/* (sha256, sha384, hmac, hkdf, x25519, aes_gcm)
  |
  \--> pki/* (asn1, x509, ecdsa_p256, trust_store, bigint256)
```

## Commands
```
# Run HTTPS GET usage script (multiple sites)
pixi run mojo -I src scripts/https_get.mojo

# Run Stage 1 Quint spec tests
pixi run test-specs

# Run crypto tests
pixi run test-crypto

# Run PKI tests
pixi run test-pki

# Run TLS tests
pixi run test-tls

# Run real HTTPS GET test
pixi run test-https

# Run all trace-based spec/implementation tests via the trace runner
pixi run test-trace

# Run everything tracked in pixi.toml
pixi run test-all
```

## Trace Runner
The trace runner (`scripts/trace_runner.mojo`) reads a JSON config and executes
Quint traces plus their corresponding Mojo implementation tests.

- Config: `tests/trace_config.json`
- Run: `pixi run test-trace`
- Override config: `mojo run -I src scripts/trace_runner.mojo path/to/config.json`

## Testing Note (Mojo 0.25.6)
Mojo 0.25.6 does **not** include the `TestSuite` test runner, so tests run via
`mojo run` instead of `mojo test`. Once `mojo == 0.25.7` is available in the
channel, the tests should be migrated to `TestSuite`.

## Setup
We use Pixi for dependencies.

```
curl -fsSL https://pixi.sh/install.sh | bash
echo 'eval "$(pixi completion --shell zsh)"' >> ~/.zshrc
pixi shell
```
