// Purpose: X25519 shared secret commutativity contract (toy model).
module crypto_x25519 {
  pure def dh(a, b) = if (a < b) a + ":" + b else b + ":" + a

  run commutative = assert(dh("a", "b") == dh("b", "a"))
}
