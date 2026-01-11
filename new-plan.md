# HTTPS Test-HTTPS Recovery Plan

Goal: make `make test-https` pass reliably and keep full suite green.

## Checklist

### 1) Review & Context
- [ ] Re-read `debug-plan.md` and `plan.md` to align with known TLS 1.3 pitfalls.
- [ ] Identify which parts of the TLS stack were changed in the PR that could affect HTTPS integration.
- [ ] Confirm `tests/integration/test_https_get.mojo` expectations (sites, redirects, status codes).

### 2) Reproduce the Failure
- [ ] Run `timeout 60s pixi run test-https` and capture the first failing site/error.
- [ ] Note whether the failure is handshake, read/write, redirect, or response parsing.
- [ ] If the failure is intermittent, re-run to confirm stability and isolate site(s).

### 3) Map to Spec + Tests (Per AGENTS process)
- [ ] Identify the failing operation (e.g., record fragmentation, CCS ignore, seq number).
- [ ] Verify the relevant Quint spec exists; add or extend a spec if missing.
- [ ] Generate a trace for the spec if the change is protocol-level.
- [ ] Add a focused Mojo unit test reproducing the failure (vector or trace-based).

### 4) Implement the Fix
- [ ] Update TLS record/handshake handling or HTTPS client logic as needed.
- [ ] Add docstrings to any new or modified important functions/traits.
- [ ] Add a brief comment if any non-obvious decision is made.
- [ ] Keep Mojo guidelines: no `mut` outputs, no tuples, prefer `@fieldwise_init`.
- [ ] If Mojo syntax is unclear, consult `docs/syntax` before editing production code.

### 5) Validate
- [ ] Re-run `timeout 60s pixi run test-https` until it passes consistently.
- [ ] Run `timeout 60s pixi run test-tls` if TLS logic changes.
- [ ] Run `timeout 60s pixi run test-trace` if trace/spec changes were made.
- [ ] Run `timeout 60s pixi run test-all`.
- [ ] Run `pixi run format`.

### 6) Final Review
- [ ] Summarize root cause and fix.
- [ ] Record any protocol learnings back in `debug-plan.md` if new.
