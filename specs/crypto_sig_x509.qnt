// Purpose: Certificate chain and hostname gating contract (toy model).
module crypto_sig_x509 {
  var hostname_ok: bool
  var signature_ok: bool

  action Init = all {
    hostname_ok' = false,
    signature_ok' = false
  }

  action AcceptHostname = all {
    hostname_ok' = true,
    signature_ok' = signature_ok
  }

  action AcceptSignature = all {
    signature_ok' = true,
    hostname_ok' = hostname_ok
  }

  action AcceptCertificate = all {
    hostname_ok,
    signature_ok,
    hostname_ok' = hostname_ok,
    signature_ok' = signature_ok
  }

  run reject_without_hostname = Init.then(AcceptSignature).then(fail(AcceptCertificate))

  run reject_without_signature = Init.then(AcceptHostname).then(fail(AcceptCertificate))

  run accept_with_both = Init
    .then(AcceptHostname)
    .then(AcceptSignature)
    .then(AcceptCertificate)
}
