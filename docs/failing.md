# Failing Sites

This document tracks HTTPS sites that currently fail with `HTTPSClient` and the reasons for their failure.

## Certificate Verification Failed

These sites fail because their CA or intermediate certificate is not in the pinned trust store in `pki/trust_store.mojo`. Currently, only `E7` (Let's Encrypt ECDSA) and `Cloudflare TLS Issuing ECC CA 3` are supported.

- `www.google.com`: Uses **Google Trust Services** (Intermediate `WR2`, Root `GTS Root R1`).
- `www.modular.com`: Uses **Google Trust Services** (Intermediate `WE1`, Root `GTS Root R1`).
- `www.cloudflare.com`: Uses **Google Trust Services** (Intermediate `GTS CA 1P5`, Root `GTS Root R1/R4`).
- `www.github.com`: Uses **Sectigo/USERTrust** (Intermediate `Sectigo ECC Domain Validation...`, Root `USERTrust ECC CA`).
- `www.wikipedia.org`: Uses **Let's Encrypt E8** (Intermediate `E8`, Root `ISRG Root X1`). The trust store only includes `E7`, so `E8` is rejected.
- `letsencrypt.org`: Uses **Let's Encrypt E8** (or similar R3/E5). Same issue as Wikipedia.
- `www.digitalocean.com`: Uses **Let's Encrypt E8**. Same issue.

## Handshake Failure (Alert 40)

These sites reject our `ClientHello`.

- `www.microsoft.com`: Server presents an **RSA Certificate** (`Microsoft Azure RSA TLS Issuing CA`). The `HTTPSClient` only advertises **ECDSA** (`SIG_ECDSA_SECP256R1_SHA256`) in the `signature_algorithms` extension.
- `www.apple.com`: Server presents an **RSA Certificate** (`Apple Public EV Server RSA CA`), but client only offers ECDSA signatures.
- `ecc256.badssl.com`: Server only supports **TLS 1.2**. The `HTTPSClient` sends `legacy_version=0x0303` (TLS 1.2) but **only** offers the TLS 1.3 cipher suite `TLS_AES_128_GCM_SHA256` (0x1301). Since the server doesn't support TLS 1.3 ciphers, it finds no common cipher suite.

## Unexpected Record Type (App Data 23)

These sites send App Data (`0x17`) when we expect a Handshake record (`0x16`).

- `www.mozilla.org`
- `www.python.org`
- `www.rust-lang.org`

**Root Cause**: The client sends the `psk_key_exchange_modes` extension but **omits** the `pre_shared_key` extension.
**Violation**: RFC 8446 Section 4.2.9 states: *"A client MUST NOT include the "psk_key_exchange_modes" extension if it does not also include the "pre_shared_key" extension."*
**Result**: Servers (likely Fastly/Varnish) reject the invalid handshake configuration, possibly with an encrypted alert or data we misinterpret.