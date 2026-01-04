// Purpose: TLS record-layer nonce/sequence contracts.
module tls_record {
  // NOTE: Minimal spec for trace-wiring only (sequence increments).
  // TODO: Add nonce derivation (iv XOR 0^32||seq), AEAD inputs/outputs, and record framing/content type rules.
  // --- State ---
  var sequence: int

  // --- Actions ---

  // Initialize the sequence to 0
  action init = all {
    sequence' = 0,
  }

  // Increment the sequence
  action step = all {
    sequence' = sequence + 1,
  }

  // --- Runs for trace generation ---

  // Generate a trace of 5 steps
  run trace_5_steps = init.then(step).then(step).then(step).then(step).then(step)

  // --- Pure logic (for reference) ---
  pure def build_nonce_simple(iv: str, seq: int): (str, int) = (iv, seq)
}
