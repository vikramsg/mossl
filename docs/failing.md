# Failing Sites

This document tracks HTTPS sites that currently fail with `HTTPSClient` and the reasons for their failure.

## Certificate Verification Failed

These sites fail because their CA or intermediate certificate is not in the pinned trust store in `pki/trust_store.mojo`. Currently, only `E7` (Let's Encrypt ECDSA) and `Cloudflare TLS Issuing ECC CA 3` are supported.

- `www.google.com`: Uses Google Trust Services (GTS Root R1).
- `www.github.com`: Uses DigiCert.
- `www.wikipedia.org`: Uses DigiCert.
- `www.modular.com`: Uses Google Trust Services.
- `letsencrypt.org`: Uses `E8` (Let's Encrypt), but our trust store only has `E7`.
- `www.cloudflare.com`: Uses Google Trust Services (GTS Root R4).
- `www.digitalocean.com`: Uses `E8` (Let's Encrypt).

## Handshake Failure (Alert 40)

These sites reject our `ClientHello`.

- `www.microsoft.com`: Returns Alert 40 (handshake_failure).
- `www.apple.com`: Returns Alert 40 (handshake_failure).
- `ecc256.badssl.com`: Returns Alert 40 (handshake_failure).

Possible reasons:
- Missing mandatory extensions (e.g., some servers might require ALPN).
- Unsupported cipher suites or groups (though we support `TLS_AES_128_GCM_SHA256` and `X25519`).
- Middlebox compatibility mode issues.

## Unexpected Record Type (App Data 23)

These sites send App Data (`0x17`) when we expect a Handshake record (`0x16`).

- `www.mozilla.org`
- `www.python.org`
- `www.rust-lang.org`

Possible reasons:
- The server might be sending a `ChangeCipherSpec` or something else that we are misinterpreting.
- TLS 1.3 middlebox compatibility mode might be causing unexpected record sequences.
- Server might be attempting a HelloRetryRequest in a way we don't handle.
