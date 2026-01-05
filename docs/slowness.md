# HTTPS GET Slowness Notes

This document captures why `make test-https`/`tests/test_https_get.mojo` can feel slow even when all sites pass.

## Conclusions

- **Sequential network I/O**: The test hits ~10 real HTTPS sites one after another. Each site requires a fresh TCP connect + TLS 1.3 handshake + HTTP request/response.
- **Handshake is CPU-heavy in Mojo**: RSA, ECDSA P-384, and BigInt arithmetic are implemented in Mojo, which is slower than highly optimized native crypto libraries. The work is the same, but it takes longer per handshake.
- **No connection reuse**: The test opens a new connection for each URL (no keep-alive or pooling), so latency adds up across sites.
- **Header parsing waits for complete header block**: The client reads until it sees the full `\r\n\r\n` terminator before parsing headers; slow servers or packet delays will stretch this phase.

## What this is not

- Not a functional TLS failure: the tests complete successfully.
- Not a single-site blocker: the time cost is distributed across many network calls.

## If we want it faster (future work, not implemented here)

- Add per-site timing in the test runner to identify the slowest hosts.
- Run a smaller subset of sites for dev iterations.
- Consider keep-alive or connection reuse in the HTTPS client.
- Optimize BigInt/crypto hot paths further or add platform-optimized paths.
