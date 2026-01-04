# Plan: Dynamic Trust Store Support

This document outlines the implementation plan to transition `ssl.mojo` from a hardcoded trust store to a dynamic one capable of loading certificates from system files or bundles.

## Objective
Enable `HTTPSClient` to load and use standard certificate bundles (like `ca-certificates.crt`), resolving failures caused by the current limited, hardcoded certificate set.

## Implementation Strategy: Spec-Driven Development
Every component will follow a **Spec-First** approach:
1.  **Define Spec**: Write a Quint specification (`specs/*.qnt`) defining the behavior (e.g., Base64 encoding/decoding invariants).
2.  **Generate Trace**: Use `quint run` to generate ITF trace files.
3.  **Mojo Trace Test**: Implement a Mojo test (`tests/test_*_trace.mojo`) that verifies the implementation against the ITF trace.
4.  **Vector Tests**: Supplement with standard test vectors in `tests/test_*.mojo`.

## Implementation Steps

### 1. Base64 Decoding (`crypto/base64.mojo`)
- **Spec**: Create `specs/crypto_base64.qnt`.
- **Trace Test**: Create `tests/test_base64_trace.mojo`.
- **Vector Tests**: Create `tests/test_base64.mojo` with RFC 4648 vectors.
- **Implementation**: Robust decoder that handles padding and ignores non-alphabet characters.

### 2. PEM Parsing (`pki/pem.mojo`)
- **Spec**: Create `specs/pki_pem.qnt`.
- **Trace Test**: Create `tests/test_pem_trace.mojo`.
- **Vector Tests**: Create `tests/test_pem.mojo`.
- **Implementation**: Logic to scan and extract content between markers.

### 3. TrustStore Loading (`pki/x509.mojo`)
- **Test First**: Create `tests/test_trust_store_load.mojo` that writes a temporary PEM file and verifies the `TrustStore` contains the expected number of certificates.
- **Implementation**: `load_from_file` and system path discovery logic.

### 4. Integration
Update `tls/connect_https.mojo` or `pki/trust_store.mojo` to optionally load the system store instead of (or in addition to) the pinned MVP certificates.

---

## Checklist

- [ ] **Base64 Infrastructure**
    - [ ] Create `crypto/base64.mojo`.
    - [ ] Implement `decode` function.
    - [ ] Add verification tests.
- [ ] **PEM Parser**
    - [ ] Create `pki/pem.mojo`.
    - [ ] Implement multi-certificate extraction logic.
- [ ] **TrustStore Extension**
    - [ ] Implement `load_from_file` in `pki/x509.mojo`.
    - [ ] Implement system path discovery.
- [ ] **Verification**
    - [ ] Verify that a local `ca-bundle.crt` can be loaded.
    - [ ] Ensure memory usage is stable when loading 100+ certificates.

## Acceptance Criteria
- `TrustStore` can be populated from a `.pem` or `.crt` file.
- All sites in `docs/failing.md` that are failing due to missing ECDSA-chain certificates (like Wikipedia/Let's Encrypt E8) pass once the appropriate CA is loaded into the store.
- **Note:** Sites requiring RSA signatures for verification will remain failing on signature verification until RSA support is added, which is outside the scope of this specific plan.
