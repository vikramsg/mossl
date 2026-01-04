"""Toy X25519 key agreement used for contract tests."""

fn public_key(secret: String) -> String:
    return secret

fn shared_secret(secret: String, peer_public: String) -> String:
    if secret < peer_public:
        return secret + ":" + peer_public
    return peer_public + ":" + secret
