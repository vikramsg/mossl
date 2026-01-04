// Purpose: AEAD integrity and determinism contracts (AES-GCM-128 in Mojo tests).
module crypto_aead {
  pure def aead_seal(k, n, a, p) = (k, n, a, p)

  // Deterministic for fixed inputs.
  run seal_deterministic = assert(aead_seal("k", "n", "a", "p") == aead_seal("k", "n", "a", "p"))

  // AAD affects output.
  run aad_changes_output = assert(aead_seal("k", "n", "a1", "p") != aead_seal("k", "n", "a2", "p"))

  // Nonce affects output.
  run nonce_changes_output = assert(aead_seal("k", "n1", "a", "p") != aead_seal("k", "n2", "a", "p"))
}
