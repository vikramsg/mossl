from collections import List

from pki.bigint import BigInt, mod_pow

from crypto.sha256 import sha256_bytes
from crypto.sha384 import sha384_bytes

from pki.asn1 import (
    DerReader,
    read_sequence_reader,
    read_integer_bytes,
    slice_bytes,
    read_bit_string,
)


fn parse_rsa_public_key(
    pubkey_bytes: List[UInt8],
) raises -> (List[UInt64], List[UInt64]):
    var reader = DerReader(pubkey_bytes)
    var seq = read_sequence_reader(reader)

    # Check if this is a SubjectPublicKeyInfo (starts with a sequence)
    # If the first element is a sequence (AlgorithmIdentifier), then it's SPKI.
    # If the first element is an integer (modulus), then it's a raw RSAPublicKey.

    var first = seq.peek_tag()
    if first == 0x30:
        # SPKI: Sequence { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
        _ = read_sequence_reader(seq)  # Skip AlgorithmIdentifier
        var bit_string = read_bit_string(seq)
        var inner_reader = DerReader(bit_string)
        var rsa_seq = read_sequence_reader(inner_reader)
        var n_bytes = read_integer_bytes(rsa_seq)
        var e_bytes = read_integer_bytes(rsa_seq)
        var n = BigInt(n_bytes)
        var e = BigInt(e_bytes)
        return (n.limbs.copy(), e.limbs.copy())
    else:
        # Raw RSAPublicKey: Sequence { modulus, publicExponent }
        var n_bytes = read_integer_bytes(seq)
        var e_bytes = read_integer_bytes(seq)
        var n = BigInt(n_bytes)
        var e = BigInt(e_bytes)
        return (n.limbs.copy(), e.limbs.copy())


fn verify_rsa_pkcs1v15(
    pubkey: List[UInt8], msg: List[UInt8], sig_bytes: List[UInt8]
) raises -> Bool:
    var parsed = parse_rsa_public_key(pubkey)
    var n_limbs = parsed[0].copy()
    var e_limbs = parsed[1].copy()

    var n_obj = BigInt(n_limbs.copy())
    var target_len = (n_obj.bit_length() + 7) // 8

    var s = BigInt(sig_bytes)
    var m_limbs = mod_pow(s.limbs.copy(), e_limbs.copy(), n_limbs.copy())

    var m_bytes = BigInt(m_limbs).to_be_bytes(target_len)

    if len(m_bytes) < 3 or m_bytes[0] != 0x00 or m_bytes[1] != 0x01:
        return False

    var pos = 2
    while pos < len(m_bytes) and m_bytes[pos] == 0xFF:
        pos += 1

    if pos >= len(m_bytes) or m_bytes[pos] != 0x00:
        return False
    pos += 1

    var payload = List[UInt8]()
    while pos < len(m_bytes):
        payload.append(m_bytes[pos])
        pos += 1

    # Check for SHA-256 prefix
    var prefix256 = List[UInt8]()
    prefix256.append(0x30)
    prefix256.append(0x31)
    prefix256.append(0x30)
    prefix256.append(0x0D)
    prefix256.append(0x06)
    prefix256.append(0x09)
    prefix256.append(0x60)
    prefix256.append(0x86)
    prefix256.append(0x48)
    prefix256.append(0x01)
    prefix256.append(0x65)
    prefix256.append(0x03)
    prefix256.append(0x04)
    prefix256.append(0x02)
    prefix256.append(0x01)
    prefix256.append(0x05)
    prefix256.append(0x00)
    prefix256.append(0x04)
    prefix256.append(0x20)

    # Check for SHA-384 prefix
    var prefix384 = List[UInt8]()
    prefix384.append(0x30)
    prefix384.append(0x41)
    prefix384.append(0x30)
    prefix384.append(0x0D)
    prefix384.append(0x06)
    prefix384.append(0x09)
    prefix384.append(0x60)
    prefix384.append(0x86)
    prefix384.append(0x48)
    prefix384.append(0x01)
    prefix384.append(0x65)
    prefix384.append(0x03)
    prefix384.append(0x04)
    prefix384.append(0x02)
    prefix384.append(0x02)
    prefix384.append(0x05)
    prefix384.append(0x00)
    prefix384.append(0x04)
    prefix384.append(0x30)

    if len(payload) == len(prefix256) + 32:
        var is_match = True
        for i in range(len(prefix256)):
            if payload[i] != prefix256[i]:
                is_match = False
                break
        if is_match:
            var h = sha256_bytes(msg)
            for i in range(32):
                if payload[len(prefix256) + i] != h[i]:
                    return False
            return True

    if len(payload) == len(prefix384) + 48:
        var is_match = True
        for i in range(len(prefix384)):
            if payload[i] != prefix384[i]:
                is_match = False
                break
        if is_match:
            var h = sha384_bytes(msg)
            for i in range(48):
                if payload[len(prefix384) + i] != h[i]:
                    return False
            return True

    return False


fn mgf1_sha256(seed: List[UInt8], out_len: Int) -> List[UInt8]:
    var out = List[UInt8]()
    var counter = UInt32(0)
    while len(out) < out_len:
        var c = List[UInt8]()
        c.append(UInt8((counter >> 24) & 0xFF))
        c.append(UInt8((counter >> 16) & 0xFF))
        c.append(UInt8((counter >> 8) & 0xFF))
        c.append(UInt8(counter & 0xFF))
        var data = List[UInt8]()
        for b in seed:
            data.append(b)
        for b in c:
            data.append(b)
        var h = sha256_bytes(data)
        for i in range(len(h)):
            if len(out) >= out_len:
                break
            out.append(h[i])
        counter += 1
    return out^


fn verify_rsa_pss_sha256(
    pubkey: List[UInt8], msg: List[UInt8], sig_bytes: List[UInt8]
) raises -> Bool:
    var parsed = parse_rsa_public_key(pubkey)
    var n_limbs = parsed[0].copy()
    var e_limbs = parsed[1].copy()

    var n_obj = BigInt(n_limbs.copy())
    var mod_bits = n_obj.bit_length()
    if mod_bits <= 1:
        return False
    var em_bits = mod_bits - 1
    var em_len = (em_bits + 7) // 8
    if len(sig_bytes) != em_len:
        return False

    var s = BigInt(sig_bytes)
    var m_limbs = mod_pow(s.limbs.copy(), e_limbs.copy(), n_limbs.copy())
    var em = BigInt(m_limbs).to_be_bytes(em_len)
    if len(em) != em_len:
        return False
    if em[em_len - 1] != 0xBC:
        return False

    var h_len = 32
    if em_len < h_len + 2:
        return False

    var masked_db_len = em_len - h_len - 1
    var masked_db = List[UInt8]()
    var i = 0
    while i < masked_db_len:
        masked_db.append(em[i])
        i += 1
    var h = List[UInt8]()
    while i < em_len - 1:
        h.append(em[i])
        i += 1

    var unused_bits = em_len * 8 - em_bits
    if unused_bits > 0:
        var mask = UInt8(0xFF) << (8 - unused_bits)
        if (masked_db[0] & mask) != 0:
            return False

    var db_mask = mgf1_sha256(h, masked_db_len)
    var db = List[UInt8]()
    for i in range(masked_db_len):
        db.append(masked_db[i] ^ db_mask[i])
    if unused_bits > 0:
        var mask2 = UInt8(0xFF) >> unused_bits
        db[0] = db[0] & mask2

    var idx = 0
    while idx < len(db) and db[idx] == 0x00:
        idx += 1
    if idx >= len(db) or db[idx] != 0x01:
        return False
    idx += 1
    var salt_len = len(db) - idx
    if salt_len != h_len:
        return False
    var salt = List[UInt8]()
    while idx < len(db):
        salt.append(db[idx])
        idx += 1

    var m_hash = sha256_bytes(msg)
    var m_prime = List[UInt8]()
    for _ in range(8):
        m_prime.append(0x00)
    for b in m_hash:
        m_prime.append(b)
    for b in salt:
        m_prime.append(b)
    var h2 = sha256_bytes(m_prime)
    if len(h2) != h_len:
        return False
    for i in range(h_len):
        if h2[i] != h[i]:
            return False
    return True
