// Purpose: TLS 1.3 handshake state machine and gating contracts (Stage 0).
module tls_handshake {
  // --- State (trace-based testing) ---
  var state: int
  var verified: int

  // --- Actions (trace-based testing) ---
  action init = all {
    state' = 0,
    verified' = 0,
  }

  action step = all {
    state < 4,
    state' =
      ite(
        state == 0,
        1,
        ite(
          state == 1,
          2,
          ite(state == 2, 3, 4)
        )
      ),
    verified' = ite(state == 2, 1, verified),
  }

  run trace_valid_handshake = init.then(step).then(step).then(step).then(step)

  pure def hs_step(s, e) = ite(
    s == "Init" and e == "SendClientHello",
    "ClientHelloSent",
    ite(
      s == "ClientHelloSent" and e == "ReceiveServerFlight",
      "ServerFlightReceived",
      ite(
        s == "ServerFlightReceived" and e == "VerifyCertificate",
        "Verified",
        ite(
          s == "Verified" and e == "SendFinished",
          "HandshakeComplete",
          "Invalid"
        )
      )
    )
  )

  pure def can_send_app(state) = state == "HandshakeComplete"

  run valid_sequence_reaches_complete =
    assert(hs_step(hs_step(hs_step(hs_step("Init", "SendClientHello"), "ReceiveServerFlight"), "VerifyCertificate"), "SendFinished") == "HandshakeComplete")

  run invalid_transition_rejected =
    assert(hs_step("Init", "SendFinished") == "Invalid")

  run gating_before_complete =
    assert(can_send_app("Init") == false)

  run gating_after_complete =
    assert(can_send_app("HandshakeComplete") == true)
}
