# HTTPS Benchmark Issues Analysis

## Summary

Two main issues were identified in the HTTPS benchmark comparison:

1. **Python failures vs Mojo success**: Python has a 30-second timeout and different redirect handling, causing some requests to fail that Mojo succeeds on.

2. **Slow requests (GitHub ~30s, Microsoft)**: Mojo's `_read_until_eof()` function blocks indefinitely when servers use HTTP keep-alive and don't provide a `Content-Length` header, waiting for an EOF that never comes.

## Issue 1: Why Python Requests Fail But Mojo Doesn't

### Root Causes

1. **Timeout Handling**
   - **Python**: Has explicit 30-second timeout (`timeout=30` in `requests.get()` or `urllib.request.urlopen()`)
   - **Mojo**: No explicit timeout - waits indefinitely for response
   - When Python hits the 30-second timeout, it raises `TimeoutError` and marks the request as failed
   - Mojo continues waiting and eventually succeeds (or hangs)

2. **Redirect Handling Differences**
   - **Python `urllib.request`**: May not automatically follow all redirect types (301, 302, 307, 308)
   - **Python `requests`**: With `allow_redirects=True`, follows redirects automatically
   - **Mojo HTTPSClient**: With `allow_redirects=True`, follows redirects via `_handle_redirect()` method
   - Some sites (wikipedia.org, cloudflare.com, digitalocean.com) may return redirects that Python's `urllib` doesn't follow, but Mojo does

3. **Status Code Interpretation**
   - **Python**: Treats any non-200 status code as failure in the benchmark
   - **Mojo**: Only treats non-200 as failure if it's not a redirect (when `allow_redirects=True`)
   - Sites returning 301/302 redirects are handled differently

### Example from Benchmark Output
- `wikipedia.org`: Python failed, Mojo succeeded - likely a redirect issue
- `cloudflare.com`: Python failed, Mojo succeeded - likely a redirect issue  
- `digitalocean.com`: Python failed, Mojo succeeded - likely a redirect issue
- `microsoft.com`: Python timed out at 30s, Mojo succeeded quickly - timeout difference

## Issue 2: Why Microsoft and GitHub Take So Long

### Root Cause: `_read_until_eof()` Blocking

The Mojo HTTPS client has a problematic code path in `src/tls/https_client.mojo`:

```mojo
// Line 167 in _read_response()
var extra = _read_until_eof(conn)
```

This function is called when:
1. Response has no `Content-Length` header
2. Response has no `Transfer-Encoding: chunked` header
3. No remaining body data in initial buffer

### The Problem

`_read_until_eof()` (lines 48-62) reads from the connection until EOF:

```mojo
fn _read_until_eof(mut conn: TLSConnectionAdapter) raises -> Bytes:
    var out = Bytes()
    var buff = Bytes(capacity=default_buffer_size)
    while True:
        var n: UInt
        try:
            n = conn.read(buff)
        except e:
            if String(e) == "EOF":
                break
            raise e
        if n == 0:
            break
        out += buff.copy()
    return out^
```

**Issues:**
1. **HTTP Keep-Alive**: Modern servers use HTTP keep-alive, keeping connections open for reuse
2. **No Timeout**: The `conn.read()` call has no timeout, so it blocks waiting for data
3. **EOF Never Comes**: With keep-alive, the server doesn't close the connection after sending the response
4. **Blocking Behavior**: The read blocks until either:
   - Server closes connection (may take minutes or never happen)
   - Network timeout (system-level, often 2-5 minutes)
   - Application timeout (none exists)

### Why GitHub and Microsoft Are Affected

From curl output:
- **GitHub**: Returns `HTTP/2 301` redirect with `content-length: 0` 
- **Microsoft**: Returns `HTTP/2 200` with `content-length: 421`

The issue occurs in `_read_response()` logic flow:

```mojo
// Line 147-158: Check content_length
var content_length = response.headers.content_length()
if content_length > 0:
    // Read exact number of bytes - WORKS CORRECTLY
    ...
    return response^

// Line 160-165: Check for remaining data in initial buffer
var remaining = reader.read_bytes().to_bytes()
if len(remaining) > 0:
    // Use remaining data - WORKS CORRECTLY
    ...
    return response^

// Line 167: FALLBACK - Read until EOF - PROBLEMATIC!
var extra = _read_until_eof(conn)
```

**The Problem:**
- When `content_length()` returns `0` (e.g., redirects with no body), the check `if content_length > 0` fails
- If there's no remaining data in the initial buffer, it falls through to `_read_until_eof()`
- `_read_until_eof()` then blocks waiting for EOF that never comes (HTTP keep-alive)

**Why It Happens:**
1. **GitHub redirect**: `content-length: 0` → `content_length()` returns 0 → skips content-length path → no remaining data → calls `_read_until_eof()` → blocks
2. **Microsoft**: Should have `content-length: 421`, but if parsing fails or returns 0, same issue
3. **Any server with keep-alive**: Connection stays open, EOF never comes, blocks indefinitely

### Solutions

1. **Add Timeout**: Implement read timeouts in `TLSConnectionAdapter.read()`
2. **Better Content-Length Handling**: Ensure `content_length()` correctly parses headers
3. **Connection Close Detection**: Detect when server indicates connection will close
4. **HTTP/2 Handling**: Properly handle HTTP/2 connection semantics
5. **Fallback Strategy**: If no content-length and no chunked encoding, read with a reasonable timeout (e.g., 5 seconds) instead of waiting for EOF

### Recommended Fix

Add a timeout to `_read_until_eof()`:

```mojo
fn _read_until_eof(mut conn: TLSConnectionAdapter, timeout_seconds: Float64 = 5.0) raises -> Bytes:
    var out = Bytes()
    var buff = Bytes(capacity=default_buffer_size)
    var start = perf_counter()
    while True:
        var elapsed = perf_counter() - start
        if elapsed > timeout_seconds:
            break  // Timeout instead of waiting forever
        var n: UInt
        try:
            n = conn.read(buff)
        except e:
            if String(e) == "EOF":
                break
            raise e
        if n == 0:
            break
        out += buff.copy()
    return out^
```

Or better: Don't use `_read_until_eof()` when `Content-Length` is present or when connection uses keep-alive.

