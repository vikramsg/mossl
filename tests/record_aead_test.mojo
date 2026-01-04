from src.crypto.aead_gcm import encrypt, decrypt

fn main() raises:
    let key = "k"
    let nonce = "n"
    let plaintext = "p"
    let (ciphertext, tag) = encrypt(key, nonce, plaintext)

    let out = decrypt(key, nonce, ciphertext, tag)
    assert(out == plaintext, "decrypt should succeed with valid tag")

    let bad = decrypt(key, nonce, ciphertext, "bad")
    assert(bad == "", "decrypt should fail with invalid tag")
