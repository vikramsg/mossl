# TLS 1.3 MVP Client Spec (HTTPS GET)

**Goal:** A pure‑Mojo TLS 1.3 *client* that can complete a real HTTPS GET to `https://example.com/`.

**Non‑Goals:** TLS 1.2, RSA, ALPN, client auth, 0‑RTT, session resumption, full X.509 ecosystem.

---

## MVP Requirements (Done)

### 1) Real TLS 1.3 Handshake (wired into `TLSSocket`)
- ✅ ClientHello/ServerHello serialization + parsing.
- ✅ HKDF‑SHA256 key schedule + transcript hashing.
- ✅ EncryptedExtensions/Certificate/CertificateVerify/Finished parsing + verification.
- ✅ Client Finished sent; handshake completes only after verification.

### 2) Record Protection (wired into `TLSSocket`)
- ✅ AES‑GCM‑128 record encryption/decryption with sequence‑derived nonces.
- ✅ Inner content type framing + tag validation.
- ✅ Monotonic sequence numbers per direction.

### 3) Certificate Validation (wired into handshake)
- ✅ X.509 parsing + signature verification.
- ✅ Trust store + chain/hostname validation.

### 4) End‑to‑End HTTPS GET
- ✅ HTTPS GET succeeds against `https://example.com/`.

---

## Deliverables (Complete)

- Real TLS handshake wired into `TLSSocket`.
- Record encryption/decryption wired into `TLSSocket`.
- Trust store loading + cert chain/hostname verification wired into handshake.
- `tests/test_https_get.mojo` passes against `https://example.com/`.

---

## Specs + Tests (Covered)

### Quint Specs
- Existing specs cover record/handshake structure: `specs/tls_record.qnt`, `specs/tls_handshake.qnt`.
- Trace‑based tests validate state progression + record sequencing:
  - `tests/test_tls_handshake_trace.mojo`
  - `tests/test_tls_record_trace.mojo`

### Mojo Tests
- RFC 8448 vectors:
  - `tests/test_tls13_rfc8448_kdf.mojo`
  - `tests/test_tls13_rfc8448_record.mojo`
- Integration:
  - `tests/test_https_get.mojo`
  - `scripts/lightbug_https_get.mojo`

### Status Checklist

| Item | Spec | Mojo Test | Pass |
| --- | --- | --- | --- |
| Real TLS 1.3 handshake + Finished verification | [x] | [x] | [x] |
| Record encryption/decryption wired into I/O | [x] | [x] | [x] |
| End‑to‑end HTTPS GET | [x] | [x] | [x] |

---

## Acceptance Criteria (Met)

- ✅ `mojo run -I . scripts/lightbug_https_get.mojo` returns HTTP 200 from `https://example.com/`.
- ✅ `mojo run -I . tests/test_https_get.mojo` passes.
