// Purpose: TLS 1.3 handshake state machine and gating invariants.
module tls13_protocol {
  var state: str
  var key_schedule_ready: bool
  var cert_verified: bool
  var appdata_enabled: bool

  action Init = all {
    state' = "start",
    key_schedule_ready' = false,
    cert_verified' = false,
    appdata_enabled' = false
  }

  action SendClientHello = all {
    state == "start",
    state' = "client_hello",
    key_schedule_ready' = key_schedule_ready,
    cert_verified' = cert_verified,
    appdata_enabled' = appdata_enabled
  }

  action ReceiveServerHello = all {
    state == "client_hello",
    state' = "server_hello",
    key_schedule_ready' = key_schedule_ready,
    cert_verified' = cert_verified,
    appdata_enabled' = appdata_enabled
  }

  action ComputeKeySchedule = all {
    state == "server_hello",
    state' = state,
    key_schedule_ready' = true,
    cert_verified' = cert_verified,
    appdata_enabled' = appdata_enabled
  }

  action ReceiveCertificate = all {
    state == "server_hello",
    state' = "cert_received",
    key_schedule_ready' = key_schedule_ready,
    cert_verified' = cert_verified,
    appdata_enabled' = appdata_enabled
  }

  action VerifyCertificate = all {
    state == "cert_received",
    state' = state,
    key_schedule_ready' = key_schedule_ready,
    cert_verified' = true,
    appdata_enabled' = appdata_enabled
  }

  action ReceiveServerFinished = all {
    state == "cert_received",
    state' = "server_finished",
    key_schedule_ready' = key_schedule_ready,
    cert_verified' = cert_verified,
    appdata_enabled' = appdata_enabled
  }

  action SendClientFinished = all {
    state == "server_finished",
    key_schedule_ready,
    cert_verified,
    state' = "handshake_complete",
    key_schedule_ready' = key_schedule_ready,
    cert_verified' = cert_verified,
    appdata_enabled' = appdata_enabled
  }

  action EnableAppData = all {
    state == "handshake_complete",
    state' = state,
    key_schedule_ready' = key_schedule_ready,
    cert_verified' = cert_verified,
    appdata_enabled' = true
  }

  run appdata_requires_handshake = Init.then(fail(EnableAppData))

  run finish_requires_keys_and_cert = Init
    .then(SendClientHello)
    .then(ReceiveServerHello)
    .then(ReceiveCertificate)
    .then(ReceiveServerFinished)
    .then(fail(SendClientFinished))

  run happy_path = Init
    .then(SendClientHello)
    .then(ReceiveServerHello)
    .then(ComputeKeySchedule)
    .then(ReceiveCertificate)
    .then(VerifyCertificate)
    .then(ReceiveServerFinished)
    .then(SendClientFinished)
    .then(EnableAppData.expect(appdata_enabled))
}
