# TLS 1.3 Debug and Modernization Plan

This plan outlines a systematic approach to debugging the Mojo TLS 1.3 implementation by comparing it against a canonical Python reference (`tlslite-ng`).

## Goals
- Build a highly instrumented Python TLS 1.3 client using `tlslite-ng`.
- Port the logic 1-1 to idiomatic Mojo.
- Perform phase-by-phase instrumented comparisons to identify and fix protocol errors.
- Document all learnings.

## Checklist

### Phase 1: Canonical Python Reference (`tlslite-ng`)
- [ ] Set up Python environment in `debug/python-tls/`.
- [ ] Install `tlslite-ng` (clone from github if needed).
- [ ] Create `debug/python-tls/tls_ref.py`:
    - [ ] Basic TLS 1.3 handshake with `example.com`.
    - [ ] Add instrumentation to log:
        - [ ] Raw ClientHello / ServerHello bytes.
        - [ ] Transcript hashes at each stage.
        - [ ] Early Secret, Handshake Secret, Master Secret.
        - [ ] Handshake Traffic Keys/IVs (Client/Server).
        - [ ] Application Traffic Keys/IVs (Client/Server).
- [ ] Verify `tls_ref.py` works end-to-end and captures all data.

### Phase 2: KDF & Key Schedule (Mojo Port)
- [ ] Create `debug/compare_keys.mojo`:
    - [ ] Port `HKDF-Expand-Label` exactly.
    - [ ] Verify against Python logs using identical inputs.
- [ ] Check Master Secret derivation 1-1.

### Phase 3: Handshake Protocol (Mojo Port)
- [ ] Instrument `src/tls/tls13.mojo` to match Python logs.
- [ ] Compare Transcript Hash after ServerHello.
- [ ] Compare Transcript Hash before/after Finished messages.
- [ ] Fix any discrepancies in message wrapping or transcript accumulation.

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
