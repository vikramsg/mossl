from src.crypto.x25519 import public_key, shared_secret

fn main() raises:
    let sk_a = "a"
    let sk_b = "b"
    let pk_a = public_key(sk_a)
    let pk_b = public_key(sk_b)
    let ss1 = shared_secret(sk_a, pk_b)
    let ss2 = shared_secret(sk_b, pk_a)
    assert(ss1 == ss2, "shared secret must be commutative")
