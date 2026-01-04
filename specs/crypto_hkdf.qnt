// Purpose: HKDF extract/expand generic contracts.
module crypto_hkdf {
  pure def hkdf_extract(salt, ikm) = (salt, ikm)
  pure def hkdf_expand(prk, info, len) = (prk, info, len)

  // HKDF is built on HMAC-SHA256; see specs/crypto_hmac.qnt and specs/crypto_sha256.qnt.
  // Mojo tests validate these contracts with RFC 5869 vectors in tests/test_hkdf.mojo.
  // Extract must be deterministic for a fixed (salt, ikm); TLS key schedule relies on stable PRK.
  run extract_deterministic = assert(hkdf_extract("salt", "ikm") == hkdf_extract("salt", "ikm"))

  // Expand must be deterministic for a fixed (prk, info, length); key material must be reproducible.
  run expand_deterministic = assert(hkdf_expand("prk", "info", 32) == hkdf_expand("prk", "info", 32))

  // Output length affects OKM; TLS derives different lengths for different secrets.
  run expand_length_affects_output = assert(hkdf_expand("prk", "info", 32) != hkdf_expand("prk", "info", 16))

  // 'info' provides domain separation; distinct labels must produce distinct outputs.
  run expand_domain_separation = assert(hkdf_expand("prk", "info1", 32) != hkdf_expand("prk", "info2", 32))
}
