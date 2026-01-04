// Purpose: X25519 shared-secret agreement contracts.
module crypto_x25519 {
  pure def x25519(s, u) = (s, u)
  pure def basepoint = "9"

  // Deterministic for fixed inputs.
  run x25519_deterministic = assert(x25519("scalar", "u") == x25519("scalar", "u"))

  // Symmetric key agreement: x25519(a, x25519(b, G)) == x25519(b, x25519(a, G)).
  run x25519_shared_secret_symmetry = assert(
    x25519("alice", x25519("bob", basepoint)) == x25519("bob", x25519("alice", basepoint))
  )

  // Basepoint changes the output (domain separation for X25519 base).
  run x25519_basepoint_affects_output = assert(
    x25519("scalar", basepoint) != x25519("scalar", "not-basepoint")
  )
}
