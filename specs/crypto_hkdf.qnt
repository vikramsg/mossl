// Purpose: HKDF extract/expand determinism and length sensitivity.
module crypto_hkdf {
  pure def hkdf_extract(salt, ikm) = "prk:" + salt + ":" + ikm
  pure def hkdf_expand(prk, info, len) = "okm:" + prk + ":" + info + ":" + len.toString()

  run extract_deterministic = assert(hkdf_extract("salt", "ikm") == hkdf_extract("salt", "ikm"))

  run expand_deterministic = assert(hkdf_expand("prk", "info", 32) == hkdf_expand("prk", "info", 32))

  run expand_length_affects_output = assert(hkdf_expand("prk", "info", 32) != hkdf_expand("prk", "info", 16))
}
