// Purpose: TLS 1.3 record layer integrity and sequencing contracts.
module tls13_record {
  var key: str
  var nonce: str
  var plaintext: str
  var seq: int

  pure def computeTag(k, n, p) = (k, n, p)

  action Init = all {
    key' = "k",
    nonce' = "n",
    plaintext' = "p",
    seq' = 0
  }

  action Decrypt(tag) = all {
    tag == computeTag(key, nonce, plaintext),
    key' = key,
    nonce' = nonce,
    plaintext' = plaintext,
    seq' = seq
  }

  action BumpSeq = all {
    seq' = seq + 1,
    key' = key,
    nonce' = nonce,
    plaintext' = plaintext
  }

  run reject_modified_tag = Init.then(fail(Decrypt(("bad", "bad", "bad"))))

  run accept_matching_tag = Init.then(Decrypt(("k", "n", "p")))

  run seq_monotonic = Init
    .then(BumpSeq.expect(seq == 1))
    .then(BumpSeq.expect(seq == 2))
}
