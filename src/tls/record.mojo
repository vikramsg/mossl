"""Toy TLS 1.3 record layer using the toy AEAD contract."""
from src.crypto.aead_gcm import encrypt, decrypt

struct RecordLayer:
    var key: String
    var nonce: String
    var seq: Int

fn new_record_layer(key: String, nonce: String) -> RecordLayer:
    return RecordLayer(key, nonce, 0)

fn encrypt_record(rl: RecordLayer, plaintext: String) -> (String, String):
    rl.seq += 1
    return encrypt(rl.key, rl.nonce, plaintext)

fn decrypt_record(rl: RecordLayer, ciphertext: String, tag: String) -> String:
    return decrypt(rl.key, rl.nonce, ciphertext, tag)
