# TLS Implementation Notes (Mojo)

This document explains **what each TLS module is**, **why design choices were made**, and how the pieces are intended to fit together as the real TLS 1.3 stack is completed.

It is intentionally opinionated: each choice lists the motivation so future work stays consistent and traceable.

---

## Goals and Non‑Goals

**Goals**
- Build a **pure Mojo TLS 1.3 client** that can drive HTTPS in `lightbug_http`.
- Keep modules small and testable, with clear boundaries and vector-based validation.
- Encode security‑critical invariants (gating, ordering, domain separation) in specs and mirror them in Mojo tests.

**Non‑Goals (for now)**
- Full TLS feature coverage (e.g., RSA, TLS 1.2, OCSP stapling, ALPN negotiation).
- Highly optimized crypto (correctness first; optimize later).

---

## High‑Level Architecture (What Modules Are For)

```
TLS
├─ tls/handshake.mojo
│   └─ Handshake state machine and ordering gates
├─ tls/record_layer.mojo
│   └─ Nonce/sequence + AEAD sealing/unsealing helpers
├─ tls/tls_socket.mojo
│   └─ Connection wrapper that enforces handshake gating
├─ tls/connect_https.mojo
│   └─ Connect + handshake (placeholder until real TLS I/O)
├─ crypto/
│   ├─ sha256.mojo, hmac.mojo, hkdf.mojo
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
**What it is:** A state machine for the TLS 1.3 handshake flow, currently with abstracted crypto gates.

**Why this choice:**
- A state machine makes **ordering constraints explicit** and testable (e.g., no application data before Finished).
- It decouples crypto correctness from protocol correctness; we can validate sequencing before full cryptographic wiring.

**What it enables:**
- Gated I/O in `TLSSocket` (no read/write until handshake complete).
- A clear place to insert real ClientHello/ServerHello parsing and verification later.

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

**Current limitation:**
- The wrapper is **gating-only** right now; it does not encrypt data yet.

---

### `tls/connect_https.mojo`
**What it is:** A convenience connector that builds a socket, then performs a TLS handshake.

**Why this choice:**
- Centralizes connection setup and handshake sequencing.
- Makes future refactors easy: when the handshake becomes real, only this module needs to change.

**Current limitation:**
- Performs only the **abstract handshake**; no real TLS record I/O.

---

### `crypto/sha256.mojo`, `crypto/hmac.mojo`, `crypto/hkdf.mojo`
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

## Why the Current `lightbug_http` Wiring Is Not Plug‑and‑Play

**Key constraint:** `lightbug_http` is hard‑typed to `TCPConnection` in the client and response parser. This prevents swapping in a TLS connection without modifying `lightbug_http` types.

**Implication:** Stage 5 **cannot be fully completed** (including the https test) until `lightbug_http` is generalized to accept a `Connection` trait (or similar) and a TLS implementation of that trait.

---

## Testing Philosophy

- Every module has a matching **Quint spec** that captures the core contract (determinism, gating, ordering).
- Every spec is mirrored by **Mojo tests** using known vectors or constrained paths.
- The goal is to fail early and locally when invariants are violated.

---

## Future Work Checklist (Implementation-Ready)

- Replace abstract handshake transitions with **real ClientHello/ServerHello** and key schedule derivations.
- Integrate record encryption in `TLSSocket` so reads/writes are transparently protected.
- Generalize `lightbug_http` to accept a TLS‑capable connection type.
- Add a real HTTPS test (`https://httpbin.org/get`) once the above is in place.
