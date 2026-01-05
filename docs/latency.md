# HTTP Client Tail Latency Analysis

This document analyzes a critical source of non-deterministic "tail latency" (observed as ~30s delays) in the `ssl.mojo` HTTPS client and details the implemented resolutions.

## Identified Issues

### 1. Blocking Read until EOF
The Mojo HTTPS client utilized a `_read_until_eof()` fallback mechanism when the end of a response could not be determined.
- **The Problem**: Modern servers use HTTP Keep-Alive, which keeps the underlying TCP/TLS connection open for future requests. 
- **Latency Impact**: Because the server does not close the connection, `read()` calls block indefinitely waiting for an EOF that never arrives. The client remained stalled until a system-level TCP timeout (often 30s-120s) or a server-side idle timeout occurred.

### 2. Header Parsing & `Content-Length: 0`
Certain HTTP responses, particularly `301/302` redirects (e.g., from GitHub) and `204 No Content` responses, provide a `Content-Length: 0` header but no body.
- **The Problem**: The client logic previously checked `if content_length > 0`. If the length was exactly `0`, it would skip the fixed-length read path and fall through to the problematic `_read_until_eof()` path.
- **Latency Impact**: This caused every redirect on affected sites to trigger the ~30s blocking behavior described above.

## Reference Code Changes

The following modifications were applied to `bench/v2/tls/https_client.mojo` to resolve these issues:

### Improved Header Detection
Update the logic in `_read_response` to recognize the presence of a `Content-Length` header even when its value is `0`.

```mojo
// Previous logic: if content_length > 0:
// Improved logic:
var content_length = response.headers.content_length()
if response.headers.get(HeaderKey.CONTENT_LENGTH) or content_length > 0:
    var body = reader.read_bytes().to_bytes()
    if len(body) < content_length:
        var extra = _read_min_bytes(conn, content_length - len(body))
        if len(extra) > 0:
            body += extra^
    // ... process body ...
    return response^
```

### Read Timeouts
Implement a wall-clock timeout in the EOF fallback loop.

```mojo
import time

fn _read_until_eof(mut conn: TLSConnectionAdapter, timeout_seconds: Float64 = 5.0) raises -> Bytes:
    var out = Bytes()
    var buff = Bytes(capacity=default_buffer_size)
    var start = time.perf_counter()
    while True:
        if time.perf_counter() - start > timeout_seconds:
            break  // Prevent indefinite blocking on Keep-Alive connections
        
        var n: UInt
        try:
            n = conn.read(buff)
        except e:
            if String(e) == "EOF": break
            raise e
        if n == 0: break
        out += buff.copy()
    return out^
```

## Testing Recommendation

**Always test these changes against `https://www.github.com/` first.** 

GitHub is an ideal test case because:
1. It consistently returns `301 Moved Permanently` redirects.
2. It uses `Content-Length: 0` for these redirects.
3. It keeps the connection open via Keep-Alive.
If the header logic or timeout logic is regression-tested, GitHub will immediately reveal any ~30-second blocking issues that would otherwise go unnoticed on sites that close connections after every request.

## Long-Term Recommendations

### Asynchronous I/O
The current architecture relies on blocking sockets. Moving to an asynchronous I/O model (e.g., using `epoll` or Mojo's future concurrency primitives) would allow the client to handle multiple concurrent requests without one stalled connection blocking the entire execution thread.

### Connection Pooling
Implementing a proper connection pool that understands Keep-Alive semantics would allow the client to proactively return a connection to the pool once the headers and body are fully consumed, rather than relying on EOF or timeouts to determine the end of a transaction.