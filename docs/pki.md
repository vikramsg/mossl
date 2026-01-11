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
