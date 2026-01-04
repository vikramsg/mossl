// Purpose: HKDF extract/expand generic contracts.
module crypto_hkdf {
  pure def hkdf_extract(salt, ikm) = (salt, ikm)
  pure def hkdf_expand(prk, info, len) = (prk, info, len)

  run extract_deterministic = assert(hkdf_extract("salt", "ikm") == hkdf_extract("salt", "ikm"))

  run expand_deterministic = assert(hkdf_expand("prk", "info", 32) == hkdf_expand("prk", "info", 32))

  run expand_length_affects_output = assert(hkdf_expand("prk", "info", 32) != hkdf_expand("prk", "info", 16))

  run expand_domain_separation = assert(hkdf_expand("prk", "info1", 32) != hkdf_expand("prk", "info2", 32))
}
