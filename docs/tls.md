# TLS Implementation Notes (Mojo)

This document explains **what each TLS module is**, **why design choices were made**, and how the pieces fit together in the current TLS 1.3 client implementation.

---

## Goals and Non‑Goals

**Goals**
- Build a **pure Mojo TLS 1.3 client** that can drive HTTPS in `lightbug_http`.
- Keep modules small and testable, with clear boundaries and vector-based validation.
- Encode security‑critical invariants (gating, ordering, domain separation) in specs and mirror them in Mojo tests.

**Non‑Goals (for now)**
- Full TLS feature coverage (e.g., RSA, TLS 1.2, OCSP stapling, ALPN negotiation, client auth, session resumption).
- Highly optimized crypto (correctness first; optimize later).

---

## High‑Level Architecture (What Modules Are For)

```
TLS
├─ tls/https_client.mojo
│   └─ Adapter for lightbug_http (Connection-like API on top of TLSSocket)
├─ tls/handshake.mojo
│   └─ Handshake state machine and ordering gates
├─ tls/record_layer.mojo
│   └─ Nonce/sequence + AEAD sealing/unsealing helpers
├─ tls/tls_socket.mojo
│   └─ Connection wrapper that enforces handshake gating
├─ tls/connect_https.mojo
│   └─ Connect + real TLS 1.3 handshake
├─ tls/tls13.mojo
│   └─ TLS 1.3 client: record I/O, key schedule, cert verification
├─ tls/transport.mojo
│   └─ Transport trait for plugging sockets into TLS13Client
├─ crypto/
│   ├─ sha256.mojo, hmac.mojo, hkdf.mojo
│   ├─ sha384.mojo
│   ├─ x25519.mojo
│   └─ aes_gcm.mojo
└─ pki/
    ├─ asn1.mojo
    ├─ x509.mojo
    ├─ ecdsa_p256.mojo
    └─ bigint256.mojo
```

---

## Module Details and Design Rationale

### `tls/handshake.mojo`
**What it is:** A state machine for the TLS 1.3 handshake flow and ordering gates.

**Why this choice:**
- A state machine makes **ordering constraints explicit** and testable (e.g., no application data before Finished).
- It decouples crypto correctness from protocol correctness; we can validate sequencing before full cryptographic wiring.

**What it enables:**
- Gated I/O in `TLSSocket` (no read/write until handshake complete).
- A clear place to validate handshake ordering and transcript progression.

---

### `tls/record_layer.mojo`
**What it is:** Record-layer nonce/sequence handling + AES‑GCM sealing (Stage 3).

**Why this choice:**
- TLS 1.3 requires **strict sequence progression and nonce derivation**; encoding this in one module avoids subtle bugs.
- Keeps AEAD use and record framing separate from handshake logic.

**What it enables:**
- Deterministic record encryption paths.
- Clean verification against AES‑GCM test vectors.

---

### `tls/tls_socket.mojo`
**What it is:** A connection wrapper that enforces handshake gating before any I/O.

**Why this choice:**
- `lightbug_http` expects a connection-like API (read/write/close). Encapsulating the TLS gate here keeps the client code simple.
- The wrapper is a natural place to eventually perform record encryption/decryption transparently.

**Current behavior:**
- Uses `TLS13Client` for record encryption/decryption once the handshake completes.

---

### `tls/connect_https.mojo`
**What it is:** A convenience connector that builds a socket, then performs a TLS handshake.

**Why this choice:**
- Centralizes connection setup and handshake sequencing.
- Makes future refactors easy: when the handshake becomes real, only this module needs to change.

**Current behavior:**
- Performs a real TLS 1.3 handshake and returns a ready `TLSSocket`.

---

### `tls/tls13.mojo`
**What it is:** The TLS 1.3 client implementation: ClientHello construction, key schedule, record protection, and certificate verification.

**Why this choice:**
- Keeps the protocol logic and cryptographic wiring in one place, while the connection wrapper (`TLSSocket`) stays thin.
- Limits scope to a **single cipher suite** for MVP correctness and testability.

**Current capability:**
- Cipher suite: `TLS_AES_128_GCM_SHA256`.
- Key exchange: `X25519`.
- Certificate verification: ECDSA P‑256 with SHA‑256 or SHA‑384.

---

### `crypto/sha256.mojo`, `crypto/sha384.mojo`, `crypto/hmac.mojo`, `crypto/hkdf.mojo`
**What they are:** Hash, MAC, and KDF primitives for the TLS 1.3 key schedule.

**Why these choices:**
- TLS 1.3 depends on **HKDF over HMAC‑SHA256**. Implementing these first makes the key schedule testable early.
- Each module is independently vector‑tested for correctness.

---

### `crypto/x25519.mojo`
**What it is:** ECDHE key exchange using Curve25519.

**Why this choice:**
- X25519 is **widely deployed**, has a fixed‑limb implementation, and avoids the need for full BigInt at this stage.
- It provides the shared secret needed for TLS 1.3 key derivation.

---

### `crypto/aes_gcm.mojo`
**What it is:** AES‑GCM‑128 for record protection.

**Why this choice:**
- TLS 1.3 mandates AEAD; AES‑GCM‑128 is a baseline cipher suite that is well‑specified with abundant test vectors.
- Provides authenticated encryption needed for record layer integrity.

---

### `pki/asn1.mojo`
**What it is:** A minimal DER decoder (TLV reader helpers).

**Why this choice:**
- X.509 parsing is **DER‑encoded ASN.1**. We only implement what TLS needs (sequences, OIDs, bit strings, etc.).
- Keeping ASN.1 minimal reduces parser surface area and risk.

---

### `pki/x509.mojo`
**What it is:** A minimal X.509 parser to extract public keys, CN/SANs, and signature material.

**Why this choice:**
- TLS certificate verification requires only a subset of X.509. Extracting the minimum prevents over‑engineering.
- Provides a clear point to implement chain building and hostname verification.

---

### `pki/ecdsa_p256.mojo`
**What it is:** P‑256 ECDSA verification on top of the minimal big‑int arithmetic.

**Why this choice:**
- ECDSA P‑256 is common in modern TLS server certificates.
- Implementing verification first enables trust decisions without pulling in RSA complexity.

---

### `pki/bigint256.mojo`
**What it is:** Minimal 256‑bit integer arithmetic for field operations.

**Why this choice:**
- ECDSA verification needs finite‑field arithmetic. A focused 256‑bit module keeps scope limited.
- This keeps performance and correctness reviewable in small steps.

---

## lightbug_http Integration

`tls/https_client.mojo` provides a small adapter that satisfies the
`lightbug_http` connection interface without changing upstream code. This keeps
TLS support local to this repo and avoids upstream API changes.

---

## Testing Philosophy

- Every module has a matching **Quint spec** that captures the core contract (determinism, gating, ordering).
- Every spec is mirrored by **Mojo tests** using known vectors or constrained paths.
- The goal is to fail early and locally when invariants are violated.

## Tests and Commands

TLS tests:
```
pixi run test-tls
```

Real HTTPS GET test:
```
pixi run test-https
```

Run everything:
```
pixi run test-all
```

---

## Future Work Checklist (Implementation-Ready)

- Add more cipher suites and signature algorithms (RSA, P‑384).
- Implement ALPN and SNI extensions beyond the current minimal set.
- Implement session resumption and key updates.
- Expand test coverage for SHA‑384 and additional cert chains.
