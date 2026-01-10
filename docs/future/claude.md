# Future Improvements for mossl

Analysis and recommendations for making this TLS implementation more generic, secure, and production-ready.

---

## 1. Making TLS Generic (Like Go's `crypto/tls`)

The current design has TLS logic tightly coupled to concrete crypto implementations. Go's TLS uses cipher suite interfaces that decouple the handshake from specific algorithms.

### Go's Architecture

```go
// Go defines an AEAD interface
type AEAD interface {
    Seal(dst, nonce, plaintext, additionalData []byte) []byte
    Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// And a cipher suite struct with function pointers
type cipherSuite struct {
    id     uint16
    keyLen int
    aead   func(key, fixedNonce []byte) AEAD
    hash   func() hash.Hash
}
```

### Required Changes

#### A. Define crypto traits

Create `src/crypto/traits.mojo`:

```mojo
trait AEAD:
    fn seal(self, nonce: List[UInt8], aad: List[UInt8], plaintext: List[UInt8]) -> (List[UInt8], List[UInt8])
    fn open(self, nonce: List[UInt8], aad: List[UInt8], ciphertext: List[UInt8], tag: List[UInt8]) -> (List[UInt8], Bool)
    fn key_size(self) -> Int
    fn nonce_size(self) -> Int
    fn tag_size(self) -> Int

trait Hash:
    fn update(mut self, data: List[UInt8])
    fn finalize(self) -> List[UInt8]
    fn output_size(self) -> Int

trait KeyExchange:
    fn generate_keypair(self) -> (List[UInt8], List[UInt8])  # (private, public)
    fn compute_shared(self, private: List[UInt8], peer_public: List[UInt8]) -> List[UInt8]
```

#### B. Create a cipher suite registry

Create `src/tls/cipher_suites.mojo`:

```mojo
struct CipherSuite[A: AEAD, H: Hash]:
    var id: UInt16
    var name: String
    var aead: A
    var hash: H

    fn derive_keys(self, secret: List[UInt8], transcript: List[UInt8]) -> TLSKeys:
        # Use self.hash for HKDF operations
        ...
```

#### C. Parameterize TLS13Client

Current implementation at `src/tls/tls13.mojo:436` is hardcoded:

```mojo
# Current (hardcoded):
struct TLS13Client[T: TLSTransport](Movable):
    ...
    # Calls aes_gcm_seal directly at line 492, sha256_bytes at line 672, etc.

# Generic version:
struct TLS13Client[T: TLSTransport, CS: CipherSuite](Movable):
    var cipher_suite: CS
    ...
    # Use self.cipher_suite.aead.seal() instead of aes_gcm_seal()
```

#### D. Separate handshake concerns

The `perform_handshake()` at lines 559-880 does everything. Split it:

```mojo
trait HandshakeHandler:
    fn send_client_hello(mut self) raises
    fn process_server_hello(mut self, msg: List[UInt8]) raises
    fn process_encrypted_extensions(mut self, msg: List[UInt8]) raises
    fn process_certificate(mut self, msg: List[UInt8]) raises
    fn process_certificate_verify(mut self, msg: List[UInt8]) raises
    fn process_finished(mut self, msg: List[UInt8]) raises
    fn send_finished(mut self) raises
```

#### E. Configuration builder pattern

Go's `tls.Config` lets users plug in custom certificate verification, cipher suite selection, and key logging. Expose similar hooks:

```mojo
var client = TLSClientBuilder()
    .with_cipher_suites([TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305])
    .with_alpn(["h2", "http/1.1"])
    .with_certificate_verifier(my_verifier)
    .build()
```

---

## 2. Increasing Confidence in Crypto Algorithms

### Current Strengths

| Practice | Implementation |
|----------|----------------|
| Test vectors | `test_aes_gcm.mojo` uses NIST vectors |
| RFC 8448 vectors | `test_tls13_rfc8448_kdf.mojo` |
| Formal specs | Quint specs in `/specs/*.qnt` |

### Improvements Needed

#### A. More comprehensive test vectors

Current AES-GCM tests (`test_aes_gcm.mojo:8-70`) cover 4 cases. NIST's full test suite has hundreds. Add:
- All vectors from NIST SP 800-38D
- Wycheproof test vectors (especially edge cases like short tags, invalid padding)

#### B. Known Answer Tests (KATs) for all primitives

For SHA-256, test:
- Empty input
- Single byte
- 55-byte (one block minus padding)
- 56-byte (exactly triggers two blocks)
- 64-byte (one full block)
- 1 million "a" characters (the NIST "long" test)

#### C. Cross-validation with established libraries

```bash
# Generate test data with OpenSSL, verify implementation matches
openssl enc -aes-128-gcm -K <key> -iv <iv> -in plaintext.bin
```

#### D. Constant-time analysis

The `aes_gcm.mojo` uses table lookups (S-box at lines 363-380). This is vulnerable to cache-timing attacks. For production crypto:
- Use bitsliced implementations, or
- Verify no secret-dependent branching/indexing

**Critical**: Tag comparison at `aes_gcm.mojo:822-823` is not constant-time:

```mojo
# Current (vulnerable to timing attack):
if input_tag_u128 != calculated_tag_u128:
    tag_valid = False

# Should be:
var diff = input_tag_u128 ^ calculated_tag_u128
tag_valid = diff == 0  # Single comparison at the end
```

#### E. Fuzz testing

```mojo
fn fuzz_aes_gcm(key: List[UInt8], iv: List[UInt8], pt: List[UInt8]):
    var sealed = aes_gcm_seal(key, iv, [], pt)
    var opened = aes_gcm_open(key, iv, [], sealed[0], sealed[1])
    assert opened[1] == True
    assert opened[0] == pt
```

#### F. Strengthen Quint specs

Current `specs/crypto_aead.qnt` tests abstract properties:

```quint
pure def aead_seal(k, n, a, p) = (k, n, a, p)  // Just returns inputs!
```

This verifies properties (determinism, nonce-sensitivity) but not correctness. Add:
- Property-based testing with random inputs
- Differential testing against a reference implementation

---

## 3. Other Improvements

### Critical Security Issues

#### A. Random number generation (`tls13.mojo:157-165`)

```mojo
fn random_bytes(count: Int) -> List[UInt8]:
    var seed = UInt64(0x9E3779B97F4A7C15)  # FIXED SEED - CATASTROPHICALLY INSECURE
    ...
```

Every connection uses the same "random" bytes. **Must** use OS CSPRNG (`/dev/urandom` on macOS/Linux).

#### B. Missing certificate checks

- No OCSP stapling/revocation checking
- No Certificate Transparency validation

#### C. No session resumption

Every connection does a full handshake (expensive for performance).

### Code Quality

#### A. Structured error handling

Current stringly-typed errors:

```mojo
raise Error("TLS handshake: CertificateVerify failed")  # Line 817
```

Better approach:

```mojo
struct TLSError:
    var kind: TLSErrorKind
    var message: String
    var alert_code: Optional[UInt8]
```

#### B. Duplicated byte conversion code

`u16_to_bytes`, `u24_to_bytes`, `u32_to_bytes` at lines 54-75 are repeated patterns. A generic approach would be cleaner.

#### C. Missing features for real-world use

- ALPN negotiation (needed for HTTP/2)
- Client certificates
- Multiple cipher suite negotiation

### Architecture

#### A. Split `perform_handshake()`

The 350-line function should be split into smaller state-machine steps (as the `handshake.mojo` state enum suggests but doesn't enforce).

---

## Priority Summary

| Area | Priority | Action |
|------|----------|--------|
| **RNG** | Critical | Replace `random_bytes()` with OS CSPRNG |
| **Tag comparison** | High | Make constant-time |
| **Generic crypto** | Medium | Define traits for AEAD, Hash, KeyExchange |
| **Test coverage** | Medium | Add NIST/Wycheproof vectors |
| **Cipher suite abstraction** | Medium | Parameterize `TLS13Client` |
| **Session resumption** | Lower | Add 0-RTT support |
