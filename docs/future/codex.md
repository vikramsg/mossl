# Codex Conclusions

This note focuses on how to make the TLS stack reusable, how to gain confidence
in crypto correctness, and what else to improve. Code snippets are minimal,
illustrative examples tied to the current repo structure.

## 1) Make TLS Generic (Reusable by Other Libraries)

### A. Decouple TLS from `lightbug_http` types
Today `src/tls/tls13.mojo` and `src/tls/tls_socket.mojo` import `Bytes` and
`TCPAddr` from `lightbug_http`. Extract a pure TLS I/O trait that uses only
byte buffers and minimal metadata.

```mojo
# src/tls/io.mojo (new)
from memory import Span
from collections import List

struct SocketAddr:
    var ip: String
    var port: Int

trait TLSTransport(Movable):
    fn read(self, mut buf: List[UInt8]) raises -> Int:
        ...

    fn write(self, buf: Span[Byte]) raises -> Int:
        ...

    fn close(mut self) raises:
        ...

    fn local_addr(self) -> SocketAddr:
        ...

    fn remote_addr(self) -> SocketAddr:
        ...
```

Then adapters implement this trait for `lightbug_http` without infecting TLS:

```mojo
# src/tls/lightbug_adapter.mojo (new)
from lightbug_http.address import TCPAddr
from lightbug_http.io.bytes import Bytes
from lightbug_http.socket import Socket
from memory import Span

from tls.io import TLSTransport, SocketAddr

struct LightbugTransport(Movable, TLSTransport):
    var socket: Socket[TCPAddr]

    fn __init__(out self, var socket: Socket[TCPAddr]):
        self.socket = socket^

    fn read(self, mut buf: List[UInt8]) raises -> Int:
        var b = Bytes(capacity=len(buf))
        var n = self.socket.receive(b)
        var i = 0
        while i < n:
            buf[i] = UInt8(b[i])
            i += 1
        return Int(n)

    fn write(self, buf: Span[Byte]) raises -> Int:
        return Int(self.socket.send(buf))

    fn close(mut self) raises:
        self.socket.close()

    fn local_addr(self) -> SocketAddr:
        var a = self.socket.local_address()
        return SocketAddr(ip=a.ip, port=Int(a.port))

    fn remote_addr(self) -> SocketAddr:
        var a = self.socket.remote_address()
        return SocketAddr(ip=a.ip, port=Int(a.port))
```

### B. Add a reusable config object
Hard-coded suites and algorithms make reuse difficult. Introduce a config struct
and pass it through to TLS13 client.

```mojo
# src/tls/config.mojo (new)
struct TLSConfig:
    var server_name: String
    var cipher_suites: List[UInt16]
    var groups: List[UInt16]
    var sig_algs: List[UInt16]
    var trust_store_path: Optional[String]
    var alpn_protocols: List[String]
```

Then use it in TLS13 client construction:

```mojo
# src/tls/tls13.mojo (signature change)
struct TLS13Client[T: TLSTransport](Movable):
    var transport: T
    var config: TLSConfig

    fn __init__(out self, var transport: T, config: TLSConfig):
        self.transport = transport^
        self.config = config
```

### C. Abstract crypto choices (cipher suite bundle)
This keeps handshake code generic over suites.

```mojo
# src/tls/cipher_suite.mojo (new)
trait CipherSuite(Movable):
    fn hash(self, data: List[UInt8]) -> List[UInt8]:
        ...

    fn hkdf_extract(self, salt: List[UInt8], ikm: List[UInt8]) -> List[UInt8]:
        ...

    fn hkdf_expand(self, prk: List[UInt8], info: List[UInt8], length: Int) -> List[UInt8]:
        ...

    fn aead_seal(self, key: List[UInt8], nonce: List[UInt8], plaintext: List[UInt8], aad: List[UInt8]) -> List[UInt8]:
        ...

    fn aead_open(self, key: List[UInt8], nonce: List[UInt8], ciphertext: List[UInt8], aad: List[UInt8]) -> List[UInt8]:
        ...
```

Then TLS uses `CipherSuite` rather than hard-coded AES‑GCM + SHA‑256.

### D. Provide a `CertificateVerifier` interface
Let other libraries supply their own PKI or verification policy.

```mojo
# src/tls/verify.mojo (new)
trait CertificateVerifier(Movable):
    fn verify_chain(self, der_chain: List[List[UInt8]], host: String) raises -> Bool:
        ...
```

Default implementation can reuse `src/pki/*`.

---

## 2) Improve Confidence in Crypto Algorithms

### A. Direct vector tests for SHA-384, ECDSA, RSA
Add tests that parse RFC or Wycheproof vectors and compare exact outputs.

```mojo
# tests/crypto/test_sha384.mojo (new)
from crypto.sha384 import sha384_bytes
from crypto.bytes import hex_to_bytes, bytes_to_hex

fn test_sha384_vectors() raises:
    var msg = hex_to_bytes("616263")  # "abc"
    var got = bytes_to_hex(sha384_bytes(msg))
    var want = "cb00753f45a35e8b..."  # RFC 6234
    assert got == want
```

### B. Differential testing against a reference
Use a script to generate random inputs and compare with a known-good library.

```python
# scripts/diff_sha256.py (example)
import os, hashlib, binascii

for _ in range(1000):
    data = os.urandom(64)
    want = hashlib.sha256(data).hexdigest()
    # call Mojo binary and compare output
```

### C. Negative tests for failure behavior
Verify that incorrect tags or signatures are rejected.

```mojo
# tests/crypto/test_aes_gcm.mojo (add)
var bad = ciphertext.copy()
bad[-1] = bad[-1] ^ UInt8(1)
var ok = aes_gcm_open(key, nonce, bad, aad)
assert len(ok) == 0  # or raises
```

### D. CSPRNG for handshake randomness
`random_bytes` in `src/tls/tls13.mojo` is deterministic. Replace it with a
secure RNG for production paths.

```mojo
# src/crypto/rng.mojo (new)
from os import urandom

fn secure_random_bytes(n: Int) -> List[UInt8]:
    var b = urandom(n)
    var out = List[UInt8]()
    for v in b:
        out.append(UInt8(v))
    return out^
```

---

## 3) Other Improvements

### A. Alert handling and record limits
Implement TLS alerts and enforce size limits in record parsing.

```mojo
# src/tls/record_layer.mojo (add check)
if len(payload) > MAX_RECORD_SIZE:
    raise Error("record too large")
```

### B. Zeroize secrets
Ensure ephemeral secrets are wiped after use.

```mojo
# src/crypto/bytes.mojo (helper)
fn zeroize(mut b: List[UInt8]):
    var i = 0
    while i < len(b):
        b[i] = 0
        i += 1
```

### C. Cleaner API surface
Expose a `TLSConn` with `read`, `write`, `close` and a `TLSListener` for servers.
Keep HTTP integration as an adapter only.

### D. Performance hotspots
Reduce per-record allocations and use fixed-size buffers where possible
(`InlineArray` for record headers, nonces, etc.).

### E. Expand protocol coverage
ALPN, session resumption, additional cipher suites, more groups beyond X25519.

---

## Summary
- Extract a library-agnostic TLS core and keep `lightbug_http` integration as an adapter.
- Add config, cipher suite, and verifier abstractions to make the TLS client reusable.
- Increase crypto confidence with direct vectors, differential tests, fuzzing,
  constant-time audits, and a CSPRNG for production.
- Improve correctness and usability with alerts, zeroization, record limits,
  a cleaner API surface, and expanded TLS feature coverage.
