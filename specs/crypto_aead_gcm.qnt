// Purpose: AEAD integrity contract for AES-GCM (toy model).
module crypto_aead_gcm {
  pure def tag(k, n, p) = "tag:" + k + ":" + n + ":" + p

  run integrity_rejects_modified = assert(tag("k", "n", "p") != tag("k", "n", "q"))

  run determinism = assert(tag("k", "n", "p") == tag("k", "n", "p"))
}
