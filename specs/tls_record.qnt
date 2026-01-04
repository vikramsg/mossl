// Purpose: TLS record-layer nonce/sequence contracts.
module tls_record {
  pure def nonce(iv, seq) = (iv, seq)

  // Nonce changes with sequence.
  run nonce_changes_with_sequence = assert(nonce("iv", 0) != nonce("iv", 1))

  // Sequence progression must be strict (no reuse).
  run sequence_strict = assert(nonce("iv", 1) != nonce("iv", 2))
}
