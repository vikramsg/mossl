from collections import List
from pki.asn1 import DerReader, read_sequence_reader, read_integer_bytes, slice_bytes
from pki.bigint import BigInt, mod_pow
from crypto.sha256 import sha256_bytes

fn parse_rsa_public_key(pubkey_bytes: List[UInt8]) raises -> (List[UInt64], List[UInt64]):
    var reader = DerReader(pubkey_bytes)
    var seq = read_sequence_reader(reader)
    var n_bytes = read_integer_bytes(seq)
    var e_bytes = read_integer_bytes(seq)
    var n = BigInt(n_bytes)
    var e = BigInt(e_bytes)
    return (n.limbs.copy(), e.limbs.copy())

fn verify_rsa_pkcs1v15(pubkey: List[UInt8], msg: List[UInt8], sig_bytes: List[UInt8]) raises -> Bool:
    var parsed = parse_rsa_public_key(pubkey)
    var n = parsed[0].copy()
    var e = parsed[1].copy()
    var s = BigInt(sig_bytes)
    var m_limbs = mod_pow(s.limbs.copy(), e.copy(), n.copy())
    var target_len = 0
    var i = len(n) - 1
    while i >= 0:
        if n[i] != 0:
            target_len = (i + 1) * 8
            break
        i -= 1
    var m_bytes = List[UInt8]()
    for k in range(len(m_limbs)):
        var v = m_limbs[k]
        for _ in range(8):
            m_bytes.append(UInt8(v & 0xFF))
            v >>= 8
    var out = List[UInt8]()
    while len(out) < target_len:
        if len(m_bytes) > 0:
            out.append(m_bytes.pop())
        else:
            out.append(0)
    if len(out) < 3 or out[0] != 0x00 or out[1] != 0x01: return False
    var pos = 2
    while pos < len(out) and out[pos] == 0xFF:
        pos += 1
    if pos >= len(out) or out[pos] != 0x00: return False
    pos += 1
    var payload = List[UInt8]()
    while pos < len(out):
        payload.append(out[pos])
        pos += 1
    var prefix = List[UInt8]()
    prefix.append(0x30); prefix.append(0x31); prefix.append(0x30); prefix.append(0x0d)
    prefix.append(0x06); prefix.append(0x09); prefix.append(0x60); prefix.append(0x86)
    prefix.append(0x48); prefix.append(0x01); prefix.append(0x65); prefix.append(0x03)
    prefix.append(0x04); prefix.append(0x02); prefix.append(0x01); prefix.append(0x05)
    prefix.append(0x00); prefix.append(0x04); prefix.append(0x20)
    if len(payload) != len(prefix) + 32: return False
    for k in range(len(prefix)):
        if payload[k] != prefix[k]: return False
    var h = sha256_bytes(msg)
    for k in range(32):
        if payload[len(prefix) + k] != h[k]: return False
    return True