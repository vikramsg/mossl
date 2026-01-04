// Purpose: HTTP I/O must be gated on handshake completion (Stage 5).
module tls_http_gating {
  pure def can_io(handshake_complete) = handshake_complete

  run no_io_before_handshake =
    assert(can_io(false) == false)

  run io_after_handshake =
    assert(can_io(true) == true)
}
