"""Toy signature verification used to match Quint gating contracts."""

fn verify(signature: String, payload: String) -> Bool:
    return signature == ("sig:" + payload)
