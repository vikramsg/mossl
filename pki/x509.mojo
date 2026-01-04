"""Minimal X.509 parser and verification helpers (Stage 4)."""
from collections import List

from pki.ecdsa_p256 import verify_ecdsa_p256, verify_ecdsa_p256_hash

from crypto.sha384 import sha384_bytes

from pki.asn1 import (
    DerReader,
    slice_bytes,
    read_sequence_reader,
    read_oid_bytes,
    read_integer_bytes,
    read_bit_string,
    read_octet_string,
)


@fieldwise_init
struct ParsedCertificate(Movable):
    var tbs: List[UInt8]
    var public_key: List[UInt8]
    var signature: List[UInt8]
    var signature_oid: List[UInt8]
    var subject_cn: List[UInt8]
    var issuer_cn: List[UInt8]
    var san_dns: List[List[UInt8]]


fn oid_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    var i = 0
    while i < len(a):
        if a[i] != b[i]:
            return False
        i += 1
    return True


fn bytes_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    var i = 0
    while i < len(a):
        if a[i] != b[i]:
            return False
        i += 1
    return True


fn read_algorithm_oid(mut reader: DerReader) -> List[UInt8]:
    var seq = read_sequence_reader(reader)
    var oid = read_oid_bytes(seq)
    # Skip optional parameters if present.
    if seq.remaining() > 0:
        _ = seq.read_tlv()
    return oid^


fn parse_name(mut reader: DerReader) -> List[UInt8]:
    var name_seq = read_sequence_reader(reader)
    var cn = List[UInt8]()
    while name_seq.remaining() > 0:
        var rdn = name_seq.read_tlv()
        if rdn.tag != UInt8(0x31):
            continue
        var rdn_reader = DerReader(
            slice_bytes(name_seq.data, rdn.start + rdn.header_len, rdn.len)
        )
        var atv = read_sequence_reader(rdn_reader)
        var oid = read_oid_bytes(atv)
        var value = atv.read_tlv()
        var value_bytes = slice_bytes(
            atv.data, value.start + value.header_len, value.len
        )
        var oid_cn = List[UInt8]()
        oid_cn.append(UInt8(0x55))
        oid_cn.append(UInt8(0x04))
        oid_cn.append(UInt8(0x03))
        if oid_equal(oid, oid_cn):
            cn = value_bytes.copy()
    return cn^


fn parse_subject_public_key_info(mut reader: DerReader) -> List[UInt8]:
    var spki = read_sequence_reader(reader)
    _ = read_algorithm_oid(spki)
    var key_bits = read_bit_string(spki)
    return key_bits^


fn parse_subject_alt_name(ext_value: List[UInt8]) -> List[List[UInt8]]:
    var out = List[List[UInt8]]()
    var reader = DerReader(ext_value)
    var seq = read_sequence_reader(reader)
    while seq.remaining() > 0:
        var slice = seq.read_tlv()
        # dNSName is context-specific tag 2 (0x82)
        if slice.tag == UInt8(0x82):
            var dns = slice_bytes(
                seq.data, slice.start + slice.header_len, slice.len
            )
            out.append(dns.copy())
    return out^


fn parse_extensions(mut reader: DerReader) -> List[List[UInt8]]:
    var sans = List[List[UInt8]]()
    var ctx = reader.read_tlv()
    if ctx.tag != UInt8(0xA3):
        return sans^
    var ctx_reader = DerReader(
        slice_bytes(reader.data, ctx.start + ctx.header_len, ctx.len)
    )
    var ext_seq = read_sequence_reader(ctx_reader)
    var oid_san = List[UInt8]()
    oid_san.append(UInt8(0x55))
    oid_san.append(UInt8(0x1D))
    oid_san.append(UInt8(0x11))
    while ext_seq.remaining() > 0:
        var ext = read_sequence_reader(ext_seq)
        var oid = read_oid_bytes(ext)
        if ext.remaining() > 0 and ext.peek_tag() == UInt8(0x01):
            _ = ext.read_tlv()  # critical
        var value = read_octet_string(ext)
        if oid_equal(oid, oid_san):
            sans = parse_subject_alt_name(value)
    return sans^


fn parse_certificate(cert_der: List[UInt8]) -> ParsedCertificate:
    var empty_sans = List[List[UInt8]]()
    var out = ParsedCertificate(
        List[UInt8](),
        List[UInt8](),
        List[UInt8](),
        List[UInt8](),
        List[UInt8](),
        List[UInt8](),
        empty_sans^,
    )

    var reader = DerReader(cert_der)
    var cert_seq = reader.read_tlv()
    if cert_seq.tag != UInt8(0x30):
        return out^
    var seq_start = cert_seq.start + cert_seq.header_len
    var seq_value = slice_bytes(cert_der, seq_start, cert_seq.len)
    var seq_reader = DerReader(seq_value)

    var tbs_slice = seq_reader.read_tlv()
    var tbs_abs_start = seq_start + tbs_slice.start
    out.tbs = slice_bytes(
        cert_der, tbs_abs_start, tbs_slice.header_len + tbs_slice.len
    )
    var tbs_value = slice_bytes(
        cert_der, tbs_abs_start + tbs_slice.header_len, tbs_slice.len
    )
    var tbs_reader = DerReader(tbs_value)

    if tbs_reader.peek_tag() == UInt8(0xA0):
        _ = tbs_reader.read_tlv()

    _ = read_integer_bytes(tbs_reader)
    _ = read_algorithm_oid(tbs_reader)
    out.issuer_cn = parse_name(tbs_reader)

    _ = read_sequence_reader(tbs_reader)  # validity
    out.subject_cn = parse_name(tbs_reader)
    out.public_key = parse_subject_public_key_info(tbs_reader)

    if tbs_reader.remaining() > 0 and tbs_reader.peek_tag() == UInt8(0xA3):
        out.san_dns = parse_extensions(tbs_reader)

    out.signature_oid = read_algorithm_oid(seq_reader)
    out.signature = read_bit_string(seq_reader)

    return out^


fn hostname_matches(cert: ParsedCertificate, hostname: List[UInt8]) -> Bool:
    for san in cert.san_dns:
        if len(san) >= 2 and san[0] == UInt8(0x2A) and san[1] == UInt8(0x2E):
            # wildcard match: *.example.com
            if len(hostname) >= len(san) - 1:
                var i = 1
                var same = True
                var offset = len(hostname) - (len(san) - 1)
                while i < len(san):
                    if san[i] != hostname[offset + i - 1]:
                        same = False
                        break
                    i += 1
                if same:
                    return True
        if len(san) == len(hostname):
            var i = 0
            var same = True
            while i < len(san):
                if san[i] != hostname[i]:
                    same = False
                    break
                i += 1
            if same:
                return True
    if len(cert.subject_cn) == len(hostname):
        var i = 0
        var same = True
        while i < len(hostname):
            if cert.subject_cn[i] != hostname[i]:
                same = False
                break
            i += 1
        if same:
            return True
    return False


struct TrustStore(Movable):
    var roots: List[List[UInt8]]

    fn __init__(out self):
        self.roots = List[List[UInt8]]()

    fn add_der(mut self, der: List[UInt8]):
        self.roots.append(der.copy())


fn verify_certificate_signature(cert: ParsedCertificate) -> Bool:
    var oid_ecdsa_sha256 = List[UInt8]()
    oid_ecdsa_sha256.append(UInt8(0x2A))
    oid_ecdsa_sha256.append(UInt8(0x86))
    oid_ecdsa_sha256.append(UInt8(0x48))
    oid_ecdsa_sha256.append(UInt8(0xCE))
    oid_ecdsa_sha256.append(UInt8(0x3D))
    oid_ecdsa_sha256.append(UInt8(0x04))
    oid_ecdsa_sha256.append(UInt8(0x03))
    oid_ecdsa_sha256.append(UInt8(0x02))
    var oid_ecdsa_sha384 = List[UInt8]()
    oid_ecdsa_sha384.append(UInt8(0x2A))
    oid_ecdsa_sha384.append(UInt8(0x86))
    oid_ecdsa_sha384.append(UInt8(0x48))
    oid_ecdsa_sha384.append(UInt8(0xCE))
    oid_ecdsa_sha384.append(UInt8(0x3D))
    oid_ecdsa_sha384.append(UInt8(0x04))
    oid_ecdsa_sha384.append(UInt8(0x03))
    oid_ecdsa_sha384.append(UInt8(0x03))
    if oid_equal(cert.signature_oid, oid_ecdsa_sha256):
        return verify_ecdsa_p256(cert.public_key, cert.tbs, cert.signature)
    if oid_equal(cert.signature_oid, oid_ecdsa_sha384):
        return verify_ecdsa_p256_hash(
            cert.public_key, sha384_bytes(cert.tbs), cert.signature
        )
    return False


fn verify_signature_with_issuer(
    cert: ParsedCertificate, issuer_pubkey: List[UInt8]
) -> Bool:
    var oid_ecdsa_sha256 = List[UInt8]()
    oid_ecdsa_sha256.append(UInt8(0x2A))
    oid_ecdsa_sha256.append(UInt8(0x86))
    oid_ecdsa_sha256.append(UInt8(0x48))
    oid_ecdsa_sha256.append(UInt8(0xCE))
    oid_ecdsa_sha256.append(UInt8(0x3D))
    oid_ecdsa_sha256.append(UInt8(0x04))
    oid_ecdsa_sha256.append(UInt8(0x03))
    oid_ecdsa_sha256.append(UInt8(0x02))
    var oid_ecdsa_sha384 = List[UInt8]()
    oid_ecdsa_sha384.append(UInt8(0x2A))
    oid_ecdsa_sha384.append(UInt8(0x86))
    oid_ecdsa_sha384.append(UInt8(0x48))
    oid_ecdsa_sha384.append(UInt8(0xCE))
    oid_ecdsa_sha384.append(UInt8(0x3D))
    oid_ecdsa_sha384.append(UInt8(0x04))
    oid_ecdsa_sha384.append(UInt8(0x03))
    oid_ecdsa_sha384.append(UInt8(0x03))
    if oid_equal(cert.signature_oid, oid_ecdsa_sha256):
        return verify_ecdsa_p256(issuer_pubkey, cert.tbs, cert.signature)
    if oid_equal(cert.signature_oid, oid_ecdsa_sha384):
        return verify_ecdsa_p256_hash(
            issuer_pubkey, sha384_bytes(cert.tbs), cert.signature
        )
    return False


fn verify_chain(
    leaf_der: List[UInt8], trust: TrustStore, hostname: List[UInt8]
) -> Bool:
    var leaf = parse_certificate(leaf_der)
    if len(leaf.tbs) == 0:
        return False
    if not hostname_matches(leaf, hostname):
        return False
    var i = 0
    while i < len(trust.roots):
        var root = parse_certificate(trust.roots[i])
        if len(root.tbs) == 0:
            i += 1
            continue
        if len(leaf.issuer_cn) > 0 and len(root.subject_cn) > 0:
            if not bytes_equal(leaf.issuer_cn, root.subject_cn):
                i += 1
                continue
        if verify_signature_with_issuer(leaf, root.public_key):
            return True
        i += 1
    return False
