# TLS 1.3 Debug and Modernization Plan

This plan outlines a systematic approach to debugging the Mojo TLS 1.3 implementation by comparing it against a canonical Python reference (`tlslite-ng`).

## Goals
- Build a highly instrumented Python TLS 1.3 client using `tlslite-ng`.
- Port the logic 1-1 to idiomatic Mojo.
- Perform phase-by-phase instrumented comparisons to identify and fix protocol errors.
- Document all learnings.

## Checklist

### Phase 1: Canonical Python Reference (`tlslite-ng`)
- [x] Set up Python environment in `debug/python-tls/`.
- [x] Install `tlslite-ng` (clone from github).
- [x] Create `debug/python-tls/tls_ref.py`:
    - [x] Basic TLS 1.3 handshake with `example.com`.
    - [x] Add instrumentation to log:
        - [x] Raw ClientHello / ServerHello bytes.
        - [x] Transcript hashes at each stage.
        - [x] Early Secret, Handshake Secret, Master Secret.
        - [x] Handshake Traffic Keys/IVs (Client/Server).
        - [x] Application Traffic Keys/IVs (Client/Server).
- [x] Verify `tls_ref.py` works end-to-end and captures all data.

## Notes & Learnings

### Phase 1: Canonical Python Reference
- **Finding**: `example.com` (and many others) often select `TLS_AES_256_GCM_SHA384`, which requires the **SHA-384** PRF.
- **Insight**: My Mojo implementation was hardcoded to SHA-256, which causes immediate `bad_record_mac` or handshake failure if the server selects a SHA-384 suite.
- **Protocol Detail**: `HKDF-Expand-Label` info structure verified:
    - 2 bytes: length
    - 1 byte: label_len (len("tls13 ") + len(label))
    - bytes: "tls13 " + label
    - 1 byte: context_len (usually hash length)
    - bytes: context (usually hash)
- **Transcript Hash**: Must be calculated *exactly* after each handshake message is sent/received.

### Phase 2: KDF & Key Schedule (Mojo Port)
- [x] Create `debug/compare_keys.mojo`:
    - [x] Port `HKDF-Expand-Label` exactly.
    - [x] Verify against Python logs using identical inputs.
- [x] Check Master Secret derivation 1-1.

## Notes & Learnings

### Phase 2: KDF & Key Schedule
- **Protocol Confirmation**: Successfully ported `HMAC-SHA384` and `HKDF-SHA384` to Mojo.
- **Verification**: Verified the Early Secret derivation against `tlslite-ng` for `example.com`.
- **Consistency**: Mojo and Python outputs for `HKDF-Extract` and `HKDF-Expand-Label` are bit-identical for SHA-384.
- **Master Secret**: Master Secret derivation follows a specific chain (Early -> Handshake -> Master). Each step must use the correct PRF.

### Phase 3: Handshake Protocol (Mojo Port)
- [ ] Create `debug/repro_handshake.mojo`:
    - [ ] Implement a `HandshakeReader` that handles fragmentation.
    - [x] Compare Transcript Hash after ServerHello (Identified mismatch!).
- [ ] Fix discrepancies in message wrapping or transcript accumulation.

## Notes & Learnings

### Phase 3: Handshake Protocol
- **Finding**: Identified a critical bug: Handshake messages can span multiple TLS records or multiple messages can be in one record.
- **Symptom**: `ServerHello` was truncated in Mojo if the record was smaller than the message, leading to transcript corruption and `auth failed`.
- **Logic Error**: The Mojo client assumes one-to-one or one-to-many mapping of Record -> Handshake Message, but does not handle many-to-one (fragmentation).
- **Requirement**: A robust `read_handshake_message()` function is needed that reads exactly N bytes (the message length) from the record stream, potentially across record boundaries.
- **ChangeCipherSpec**: Must be silently ignored if encountered in the record stream during handshake.

### Phase 4: Record Layer (Mojo Port)
- [ ] Verify AAD construction 1-1.
- [ ] Verify Nonce (XOR) logic 1-1.
- [ ] Verify GHASH / AES-GCM tag calculation 1-1 for multi-block responses.

### Phase 5: Final Integration
- [ ] Run full `test-https` and ensure 10/10 success.
- [ ] Update `bench/README.md` with verified performance.

## Notes & Learnings

### Phase 0: Initial Analysis
- *Observation*: The current Mojo handshake loop is linear and assumes a fixed record order.
- *Insight*: Sequence number drift is a major suspect for `auth failed` errors when non-AppData records (like SessionTickets) are received.
- *Learnings*: (To be added during execution)
