// Purpose: HMAC-SHA256 generic contracts.
module crypto_hmac {
  pure def hmac(k, m) = (k, m)

  // HMAC must be deterministic for a fixed key and message.
  run deterministic = assert(hmac("key", "msg") == hmac("key", "msg"))

  // Changing the key must change the MAC output.
  run key_separation = assert(hmac("key1", "msg") != hmac("key2", "msg"))

  // Changing the message must change the MAC output.
  run msg_separation = assert(hmac("key", "msg1") != hmac("key", "msg2"))
}
