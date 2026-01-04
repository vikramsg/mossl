// Purpose: Certificate signature and chain gating contracts (Stage 4).
module pki_chain {
  pure def can_connect(chain_verified) = chain_verified

  run gating_requires_valid_chain =
    assert(can_connect(false) == false)

  run gating_allows_valid_chain =
    assert(can_connect(true) == true)
}
