// Purpose: SHA-256 generic contracts.
module crypto_sha256 {
  pure def sha256(x) = x

  // Hashing must be deterministic for a fixed input.
  run deterministic = assert(sha256("input") == sha256("input"))

  // Different inputs must not collide under this abstract model.
  run input_separation = assert(sha256("input1") != sha256("input2"))
}
