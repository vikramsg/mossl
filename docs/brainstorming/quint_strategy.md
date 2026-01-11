# Quint Specification Strategy

## Strategy: Protocol Logic over Primitives

The core strategy is to focus Quint modeling on **protocol rules** (state and sequence) rather than **primitive implementation** (bit-twiddling).

### 1. Active Protocol Models
These models are being developed or improved to provide high-fidelity verification of the TLS and PKI layers.

| Spec | Focus | Goal |
| :--- | :--- | :--- |
| `tls_handshake.qnt` | State Machine | Verify message sequencing and error states in the TLS 1.3 handshake. |
| `tls_record.qnt` | Sequence/Nonces | Verify `IV XOR Seq` nonce derivation and sequence number increments. |
| `pki_path_validation.qnt` | Chain Rules | (In Progress) Model X.509 path building: Subject/Issuer matching and signature chains. |
| `tls_key_schedule.qnt` | Key Tree | (Planned) Model the sequence of HKDF-Extract/Expand calls in TLS 1.3. |

### 2. Deleted Trivial Specs
The following were deleted as they provided zero verification value over standard Mojo unit tests with RFC test vectors.
- `crypto_sha256.qnt`
- `crypto_hmac.qnt`
- `crypto_aead.qnt`
- `tls_http_gating.qnt`
- `crypto_hkdf.qnt` (To be replaced by `tls_key_schedule.qnt`)
- `pki_chain.qnt` (To be replaced by `pki_path_validation.qnt`)

### 3. Utility Specs
- **`bigint_pow.qnt`**: Models modular exponentiation for `bigint.mojo`.
- **`crypto_x25519.qnt`**: Models DH symmetry properties.
