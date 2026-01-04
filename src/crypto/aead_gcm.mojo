"""Toy AEAD-GCM implementation matching the Quint contract tests."""

fn compute_tag(key: String, nonce: String, plaintext: String) -> String:
    return "tag:" + key + ":" + nonce + ":" + plaintext

fn encrypt(key: String, nonce: String, plaintext: String) -> (String, String):
    let tag = compute_tag(key, nonce, plaintext)
    // Toy cipher: ciphertext is the plaintext.
    return (plaintext, tag)

fn decrypt(key: String, nonce: String, ciphertext: String, tag: String) -> String:
    let expected = compute_tag(key, nonce, ciphertext)
    if tag == expected:
        return ciphertext
    return ""
