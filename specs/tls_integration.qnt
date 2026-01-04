// Purpose: Integration gating between TLS handshake completion and HTTP I/O.
module tls_integration {
  var handshake_complete: bool

  action Init = all {
    handshake_complete' = false
  }

  action HandshakeComplete = all {
    handshake_complete' = true
  }

  action SendHttp = all {
    handshake_complete,
    handshake_complete' = handshake_complete
  }

  run reject_send_before_handshake = Init.then(fail(SendHttp))

  run allow_send_after_handshake = Init.then(HandshakeComplete).then(SendHttp)
}
