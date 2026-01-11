# HTTPS Test-HTTPS Recovery Plan

Goal: make `make test-https` pass reliably and keep full suite green.

## Checklist

### 1) Review & Context
- [x] Re-read `debug-plan.md` and `plan.md` to align with known TLS 1.3 pitfalls.
- [x] Identify which parts of the TLS stack were changed in the PR that could affect HTTPS integration.
- [x] Confirm `tests/integration/test_https_get.mojo` expectations (sites, redirects, status codes).

### 2) Reproduce the Failure
- [x] Run `timeout 60s pixi run test-https` and capture the first failing site/error.
- [x] Note whether the failure is handshake, read/write, redirect, or response parsing.
- [x] If the failure is intermittent, re-run to confirm stability and isolate site(s).

### 3) Map to Spec + Tests (Per AGENTS process)
- [x] Identify the failing operation (e.g., record fragmentation, CCS ignore, seq number).
- [x] Verify the relevant Quint spec exists; add or extend a spec if missing (N/A for this fix).
- [x] Generate a trace for the spec if the change is protocol-level (N/A for this fix).
- [x] Add a focused Mojo unit test reproducing the failure (vector or trace-based) (N/A for this fix).

### 4) Implement the Fix
- [x] Update TLS record/handshake handling or HTTPS client logic as needed.
- [x] Add docstrings to any new or modified important functions/traits (N/A for this fix).
- [x] Add a brief comment if any non-obvious decision is made (N/A for this fix).
- [x] Keep Mojo guidelines: no `mut` outputs, no tuples, prefer `@fieldwise_init`.
- [x] If Mojo syntax is unclear, consult `docs/syntax` before editing production code (N/A for this fix).
- [x] Replace debug `print` calls with the Mojo `logger` where appropriate (tests).
- [x] Configure logger output to be formatted like other languages (time, function, line number) when feasible.
- [x] Remove debug-only `print` calls from production code.
- [x] Fix any compiler warnings introduced or surfaced by changes.
- [x] Create a shared logger utility under `src/utils` and switch call sites to import it.

### 5) Validate
- [x] Re-run `timeout 60s pixi run test-https` until it passes consistently.
- [x] Run `timeout 60s pixi run test-tls` if TLS logic changes (covered by `test-all`).
- [x] Run `timeout 60s pixi run test-trace` if trace/spec changes were made (covered by `test-all`).
- [x] Run `timeout 60s pixi run test-all`.
- [x] Run `pixi run format`.
- [x] Run `timeout 300s pixi run bash bench/bench_https_get.sh` and check for regressions.

### 6) Final Review
- [x] Summarize root cause and fix.
- [x] Record any protocol learnings back in `debug-plan.md` if new (N/A for this fix).
