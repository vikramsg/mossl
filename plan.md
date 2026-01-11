# PKI Implementation Plan

## Goals
- Implement RFC 5280-compliant path validation for TLS 1.3 server auth.
- Keep parsing and validation deterministic, testable, and trace-verified.
- Provide precise failure reasons for TLS error reporting.

## Data Model
- ParsedCertificate (zero-copy view over DER):
  - Raw DER slice, TBS slice, signature algo OID, signature bits.
  - Subject DN (full), Issuer DN (full).
  - SubjectPublicKeyInfo (SPKI), Subject Key Identifier (SKID), Authority Key Identifier (AKID).
  - Validity (notBefore, notAfter) as unix seconds.
  - Extensions: BasicConstraints (is_ca, path_len), KeyUsage, ExtendedKeyUsage,
    SubjectAltName (DNS/IP), NameConstraints (optional), PolicyConstraints (optional).
- TrustStore:
  - Indexed by subject DN and by SKID for O(1) candidate lookup.
  - Track trust anchors with constraints (if present).

## Parsing (ASN.1/DER)
- Build a zero-copy DerReader that returns spans into the original byte buffer.
- Parse full X.509 structure:
  - TBSCertificate (version, serial, signature, issuer, validity, subject, SPKI, extensions).
  - SignatureAlgorithm and signatureValue.
- Decode and validate extensions:
  - BasicConstraints (critical for CA); KeyUsage; ExtendedKeyUsage; SAN; AKID/SKID.
- Reject malformed DER or unknown critical extensions.

## Validation Flow (RFC 5280 core)
1. Parse leaf and intermediates into ParsedCertificate list.
2. Hostname verification:
   - Prefer SAN dNSName/iPAddress; fall back to CN only when SAN absent.
   - Enforce wildcard rules (left-most label only, no partial label match).
3. Path building:
   - Build candidate chains by subject/issuer match + AKID/SKID when present.
   - Prefer trust anchors from TrustStore; support multiple possible parents.
4. For each candidate path, validate in order from leaf -> root:
   - Signature verification for each cert using issuer SPKI.
   - Validity window checks at evaluation time.
   - BasicConstraints: intermediates must be CA, enforce pathLenConstraint.
   - KeyUsage: keyCertSign for CA, digitalSignature for leaf.
   - ExtendedKeyUsage: ServerAuth required for leaf.
   - NameConstraints (if present on CA) applied to all subordinates.
5. Accept if any path validates; otherwise return the first failure reason based on
   deterministic preference order.

## Error Model
- Replace Bool returns with Result[Ok, PkiError].
- PkiError variants: ParseError, HostnameMismatch, InvalidSignature, Expired,
  NotYetValid, NotCA, PathLenExceeded, UntrustedRoot, UnknownCriticalExtension,
  InvalidKeyUsage, InvalidExtendedKeyUsage, NameConstraintViolation.

## Spec + Tests (Process)
1. Add/extend Quint spec for path building, signature linkage, time validity,
   basic constraints, and key usage rules.
2. Generate traces for success and each failure class.
3. Add unit tests for parser (DER edge cases) and validation rules.
4. Implement validation in Mojo to satisfy trace + unit tests.
5. Run `make test-all` and `make format`.

## Integration
- Update TLS handshake certificate validation to use new Result type and surface
  errors in alerts/logging.
- Keep trust store loading configurable; support system store + pinned roots.

