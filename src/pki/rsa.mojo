"""RSA verification and PKCS#1 v1.5 / PSS padding support."""

from collections import List

from crypto.sha256 import sha256
from crypto.sha384 import sha384_bytes

from pki.asn1 import (
    parse_rsa_public_key,
    DerReader,
    read_sequence_reader,
    read_bit_string,
    read_integer_bytes,
)
from pki.bigint import (
    BigInt,
    mod_pow,
    bytes_to_bigint,
    bigint_to_bytes,
    bigint_compare,
)


struct RSAPublicKeyParts:
    """Modulus and exponent of an RSA public key."""

    var n: List[UInt64]
    var e: List[UInt64]

    fn __init__(out self, var n: List[UInt64], var e: List[UInt64]):
        self.n = n^
        self.e = e^

    fn __moveinit__(out self, deinit other: Self):
        self.n = other.n^
        self.e = other.e^


fn parse_rsa_pub_key_parts(der: List[UInt8]) raises -> RSAPublicKeyParts:
    """Parses a DER-encoded RSA public key into its components (n, e).
    Supports both raw RSAPublicKey and SubjectPublicKeyInfo formats.
    """
    var reader = DerReader(der)
    var seq = read_sequence_reader(reader)

    var first = seq.peek_tag()
    if first == 0x30:
        # SPKI: Sequence { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
        _ = read_sequence_reader(seq)  # Skip AlgorithmIdentifier
        var bit_string = read_bit_string(seq)
        var inner_reader = DerReader(bit_string)
        var rsa_key = parse_rsa_public_key(inner_reader.data)
        return RSAPublicKeyParts(rsa_key.n.copy(), rsa_key.e.copy())
    else:
        # Raw RSAPublicKey: Sequence { modulus, publicExponent }
        var rsa_key = parse_rsa_public_key(der)
        return RSAPublicKeyParts(rsa_key.n.copy(), rsa_key.e.copy())


fn verify_rsa_pkcs1v15(
    pub_key_der: List[UInt8], msg: List[UInt8], sig: List[UInt8]
) raises -> Bool:
    """Verifies an RSA PKCS#1 v1.5 signature with SHA-256 or SHA-384."""
    var parts = parse_rsa_pub_key_parts(pub_key_der)
    var n_limbs = parts.n.copy()
    var e_limbs = parts.e.copy()

    var n_obj = BigInt(n_limbs.copy())
    var target_len = (n_obj.bit_length() + 7) // 8

    var s = bytes_to_bigint(sig)
    var m_limbs = mod_pow(s, e_limbs, n_limbs)
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
    var prefix256 = List[UInt8](
        0x30,
        0x31,
        0x30,
        0x0D,
        0x06,
        0x09,
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        0x01,
        0x05,
        0x00,
        0x04,
        0x20,
    )
    # Check for SHA-384 prefix
    var prefix384 = List[UInt8](
        0x30,
        0x41,
        0x30,
        0x0D,
        0x06,
        0x09,
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        0x02,
        0x05,
        0x00,
        0x04,
        0x30,
    )

    if len(payload) == len(prefix256) + 32:
        var is_match = True
        for i in range(len(prefix256)):
            if payload[i] != prefix256[i]:
                is_match = False
                break
        if is_match:
            var h = sha256(msg)
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


fn mgf1_sha256(seed: List[UInt8], out_len: Int) raises -> List[UInt8]:
    """MGF1 mask generation function based on SHA-256."""
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
        var h = sha256(data)
        for i in range(32):
            if len(out) >= out_len:
                break
            out.append(h[i])
        counter += 1
    return out^


fn verify_rsa_pss_sha256(
    pub_key_der: List[UInt8], msg: List[UInt8], sig: List[UInt8]
) raises -> Bool:
    """Verifies an RSA PSS signature with SHA-256."""
    var parts = parse_rsa_pub_key_parts(pub_key_der)
    var n_limbs = parts.n.copy()
    var e_limbs = parts.e.copy()

    var n_obj = BigInt(n_limbs.copy())
    var mod_bits = n_obj.bit_length()
    if mod_bits <= 1:
        return False
    var em_bits = mod_bits - 1
    var em_len = (em_bits + 7) // 8
    if len(sig) != em_len:
        return False

    var s = bytes_to_bigint(sig)
    var m_limbs = mod_pow(s, e_limbs, n_limbs)
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
    for j in range(masked_db_len):
        db.append(masked_db[j] ^ db_mask[j])
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

    var m_hash = sha256(msg)
    var m_prime = List[UInt8]()
    for _ in range(8):
        m_prime.append(0x00)
    for i in range(32):
        m_prime.append(m_hash[i])
    for b in salt:
        m_prime.append(b)
    var h2 = sha256(m_prime)
    for j in range(h_len):
        if h2[j] != h[j]:
            return False
    return True
