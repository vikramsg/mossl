# Public Key Infrastructure (PKI)

This document describes the PKI implementation in `ssl.mojo`, focusing on certificate parsing, trust management, and path validation.

## Architecture Overview

The PKI layer is responsible for establishing trust in the server's identity during the TLS handshake. It bridges the gap between raw bytes (ASN.1 DER) and cryptographic verification (RSA/ECDSA).

```ascii
+-------------------------------------------------------------+
|                       TLS Handshake                         |
| (Receives Certificate Message: [Leaf, Inter1, Inter2, ...]) |
+------------------------------+------------------------------+
                               |
                               v
+------------------------------+------------------------------+
|                    x509.verify_chain()                      |
|  1. Parse DER -> ParsedCertificate                          |
|  2. Check Hostname (Leaf)                                   |
|  3. Build Chain -> [Leaf] -> [Inter] -> [Root]              |
|  4. Validate Rules (Signatures, Dates, CA Flags)            |
+--------------+---------------+--------------+---------------+
               |               |              |
               v               v              v
       +-------+-------+  +----+----+  +------+-------+
       |   asn1.mojo   |  | pem.mojo|  | trust_store. |
       | (DER Decoder) |  | (Parser)|  | (Root Certs) |
       +---------------+  +---------+  +--------------+
               |
               v
       +-------+-------+
       | Crypto Layer  |
       | (RSA, ECDSA)  |
       +---------------+
```

## Path Validation Logic

Validation follows a linear walk from the **Leaf** (the server's certificate) to a **Trusted Root** found in the system store.

**The Players:**
*   **The Client**: Your computer (or browser). The Client **initiates** the validation because it does not trust the Server by default.
*   **The Server**: The website you are visiting (e.g., `google.com`). It sends a "bundle" of certificates to prove its identity.
*   **The Hostname**: The address you typed in your browser.
*   **The Chain**: A list of certificates sent by the server. Think of it like a **Chain of Trust**: the website (Leaf) is trusted by an Intermediate, which is trusted by another, until we reach a "Root" that your computer already knows and trusts.
*   **Certificate C (The Child)**: The certificate we are currently checking. We start with the "Leaf" (the one for the website itself).
*   **Certificate P (The Parent)**: The certificate that "vouches" for the child. It is also called the **Issuer**.

1.  **Hostname Matching**: The **Client** checks that the "Leaf" certificate the **Server** sent actually belongs to the **Hostname** you tried to visit. This prevents a malicious site from using a valid certificate belonging to someone else.
2.  **Subject-Issuer Link**: For every certificate **C** in the chain, it must point to a parent. The "Issuer" name written on Certificate **C** must match the "Subject" name written on Certificate **P**.
3.  **Signature Verification**: The **Client** performs a mathematical check to ensure that Certificate **P** actually signed Certificate **C**. It is like verifying a physical wax seal; if the seal is broken or was made with the wrong stamp, the link is invalid.
4.  **Constraints (The CA Check)**: Not every certificate is allowed to vouch for others. The **Client** checks a special flag called "Basic Constraints" to ensure that Parent **P** is a legitimate **Certificate Authority (CA)** and not just another website certificate pretending to be one.
5.  **The Trust Store**: This process repeats until the **Client** finds a Parent that is already in its "Trust Store"—a list of "Golden Roots" (like DigiCert or Let's Encrypt) that were pre-installed on your computer when you bought it.

## Why use a Formal Specification (Quint)?

Path validation is one of the most security-critical and error-prone parts of any SSL/TLS library. It is a prime candidate for formal specification for several reasons:

### 1. Sequential Logic & State
Validation is a stateful process. At each step, we maintain a "current certificate" and look for its parent. Quint excels at modeling these transitions and ensuring the final state (`Valid` or `Invalid`) is reached correctly.

### 2. Edge Case Exhaustion
Manual unit tests often miss complex chain structures, such as:
- **Self-signed intermediates**: Identifying when a chain loops.
- **Cross-signing**: When a certificate has multiple potential valid paths.
- **Malicious Leafs**: A leaf trying to act as a CA.
Quint's model checker can exhaustively test these "adversarial" topologies.

### 3. Rule Integrity (The "Basic Constraints" Trap)
Many historic vulnerabilities (e.g., CVE-2014-0092) occurred because a library checked the signature but forgot to check if the signer was actually a CA. By defining the "Rules of the Game" in Quint, we ensure the Mojo implementation cannot reach a `Valid` state unless *all* conditions (Signature AND CA flag AND Subject/Issuer) are met simultaneously.

### 4. Trace-Based Testing
By generating ITF traces from the Quint spec, we can "play back" valid and invalid chains through the Mojo `verify_chain` function, ensuring the code adheres perfectly to the formal model.

## Implementation Considerations

This section compares the `ssl.mojo` approach with standard libraries like OpenSSL, Go (`crypto/x509`), and Rust (`webpki`).

### 1. Architectural Layering
In mature libraries, PKI is a "Middle-Ware" layer that bridges core crypto and the protocol.

*   **Separation**:
    *   **Go**: Separates [crypto/tls](https://pkg.go.dev/crypto/tls) (protocol) from [crypto/x509](https://pkg.go.dev/crypto/x509) (PKI logic).
    *   **OpenSSL**: Distinctly separates [libssl](https://www.openssl.org/docs/manmaster/man7/ssl.html) (TLS/SSL) and [libcrypto](https://www.openssl.org/docs/manmaster/man7/crypto.html) (primitives and X.509 logic).
    *   **Rust**: [rustls](https://github.com/rustls/rustls) handles TLS logic but delegates certificate validation to the [webpki](https://github.com/rustls/webpki) crate.

### 2. Data Structure Shapes
Efficient PKI implementations use specific structures to handle the complexity of X.509:

*   **ParsedCertificate**: Modern libraries like Go keep a pointer to the original `Raw` bytes (see the [Certificate struct definition](https://github.com/golang/go/blob/master/src/crypto/x509/x509.go)). This ensures signature verification is performed on the exact original ASN.1 DER bytes.
*   **TrustStore / CertPool**:
    *   **Go**: The `CertPool` uses a map-based lookup in [findPotentialParents](https://github.com/golang/go/blob/master/src/crypto/x509/cert_pool.go) to find issuers by name in $O(1)$ or $O(log N)$ instead of linear $O(N)$.
    *   **OpenSSL**: Employs [X509_STORE_CTX](https://www.openssl.org/docs/manmaster/man3/X509_STORE_CTX_new.html) to manage the state of a single verification path, preventing stack overflows from circular chains.

## Recommendations for Improvement

Based on an analysis of the current `ssl.mojo` codebase versus industry standards (Go, rustls, OpenSSL), the following architectural changes are recommended:

### 1. Shift to Zero-Copy Slicing
*   **Current Issue**: `ParsedCertificate` and `DerReader` currently use `slice_bytes`, which copies data into new `List[UInt8]` instances. This is a significant memory and CPU overhead.
*   **Recommendation**: Refactor `DerReader` and `ParsedCertificate` to use `Span[UInt8]` or a custom `ByteView`. The `ParsedCertificate` should hold views into the original DER buffer rather than owned copies of the `TBS`, `Subject`, and `Issuer` fields.

### 2. Optimize TrustStore Lookup
*   **Current Issue**: `TrustStore` uses a linear search ($O(N)$) through a list of DER bytes. This makes chain verification extremely slow as the number of trusted roots grows.
*   **Recommendation**: Implement a `CertPool` that uses a `Dict[Bytes, ParsedCertificate]` where the key is a hash of the `Subject` name or the `SubjectKeyIdentifier`. This will allow $O(1)$ parent discovery during path building.

### 3. Implement Critical Validation Checks
*   **Current Issue**: The current implementation is missing several "security critical" checks required by RFC 5280.
*   **Recommendation**:
    *   **Basic Constraints**: Update `parse_extensions` to decode the CA flag and verify it in `verify_chain`.
    *   **Validity Dates**: Stop skipping the 'validity' field in `parse_certificate`. Implement a check against the system clock.
    *   **Key Usage**: Ensure certificates used in the handshake have the "Server Auth" extended key usage and "Digital Signature" key usage.

### 4. Improve Error Granularity
*   **Current Issue**: `verify_chain` returns a simple `Bool`, making it impossible for the TLS layer to report *why* a connection failed.
*   **Recommendation**: Replace boolean returns with a `Result` or `Error` type that distinguishes between `Expired`, `HostnameMismatch`, `UntrustedRoot`, and `InvalidSignature`.
