"""Minimal X.509 parser and verification helpers (Stage 4)."""
from collections import List

from pki_instrumented.ecdsa_p256 import verify_ecdsa_p256, verify_ecdsa_p256_hash
from pki_instrumented.ecdsa_p384 import verify_ecdsa_p384_hash
from pki_instrumented.rsa import verify_rsa_pkcs1v15

from crypto_instrumented.sha384 import sha384_bytes

from pki_instrumented.asn1 import (
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

    fn copy(self) -> ParsedCertificate:
        var new_san = List[List[UInt8]]()
        for i in range(len(self.san_dns)):
            new_san.append(self.san_dns[i].copy())
        return ParsedCertificate(
            self.tbs.copy(),
            self.public_key.copy(),
            self.signature.copy(),
            self.signature_oid.copy(),
            self.subject_cn.copy(),
            self.issuer_cn.copy(),
            new_san.copy(),
        )


fn to_string(b: List[UInt8]) -> String:
    var s = String("")
    for i in range(len(b)):
        s += chr(Int(b[i]))
    return s


fn to_hex(b: List[UInt8]) -> String:
    var s = String("")
    var chars = String("0123456789abcdef")
    for i in range(len(b)):
        var v = Int(b[i])
        s += chars[v >> 4]
        s += chars[v & 0x0F]
    return s


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


fn read_algorithm_oid(mut reader: DerReader) raises -> List[UInt8]:
    var seq = read_sequence_reader(reader)
    var oid = read_oid_bytes(seq)
    # Skip optional parameters if present.
    if seq.remaining() > 0:
        _ = seq.read_tlv()
    return oid.copy()


fn parse_name(mut reader: DerReader) raises -> List[UInt8]:
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
    return cn.copy()


fn parse_subject_public_key_info(mut reader: DerReader) raises -> List[UInt8]:
    var spki = read_sequence_reader(reader)
    _ = read_algorithm_oid(spki)
    var key_bits = read_bit_string(spki)
    return key_bits.copy()


fn parse_subject_alt_name(ext_value: List[UInt8]) -> List[List[UInt8]]:
    var out = List[List[UInt8]]()
    try:
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
    except:
        pass
    return out.copy()


fn parse_extensions(mut reader: DerReader) raises -> List[List[UInt8]]:
    var sans = List[List[UInt8]]()
    var ctx = reader.read_tlv()
    if ctx.tag != UInt8(0xA3):
        return sans.copy()
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
    return sans.copy()


fn parse_certificate(cert_der: List[UInt8]) raises -> ParsedCertificate:
    var empty_sans = List[List[UInt8]]()
    var out = ParsedCertificate(
        List[UInt8](),
        List[UInt8](),
        List[UInt8](),
        List[UInt8](),
        List[UInt8](),
        List[UInt8](),
        empty_sans.copy(),
    )

    var reader = DerReader(cert_der)
    var cert_seq = reader.read_tlv()
    if cert_seq.tag != UInt8(0x30):
        return out.copy()
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

    return out.copy()


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


from pki_instrumented.pem import parse_pem
from crypto_instrumented.base64 import base64_decode


struct TrustStore(Movable):
    var roots: List[List[UInt8]]

    fn __init__(out self):
        self.roots = List[List[UInt8]]()

    fn copy(self) -> TrustStore:
        var out = TrustStore()
        for i in range(len(self.roots)):
            out.add_der(self.roots[i].copy())
        return out^

    fn add_der(mut self, der: List[UInt8]):
        self.roots.append(der.copy())

    fn load_pem(mut self, pem_data: String):
        var blocks = parse_pem(pem_data)
        for i in range(len(blocks)):
            var der = base64_decode(blocks[i])
            if len(der) > 0:
                self.add_der(der)

    fn load_from_file(mut self, path: String) raises:
        var f = open(path, "r")
        var data = f.read()
        f.close()
        self.load_pem(data)


fn load_system_trust_store() -> TrustStore:
    var trust = TrustStore()
    var paths = List[String]()
    paths.append("/etc/ssl/certs/ca-certificates.crt")
    paths.append("/etc/pki/tls/certs/ca-bundle.crt")
    paths.append("/etc/ssl/ca-bundle.pem")
    paths.append("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
    paths.append("/etc/ssl/cert.pem")

    for i in range(len(paths)):
        try:
            trust.load_from_file(paths[i])
            if len(trust.roots) > 0:
                return trust.copy()
        except:
            pass
    return trust.copy()


fn verify_certificate_signature(cert: ParsedCertificate) raises -> Bool:
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

    var oid_rsa_sha256 = List[UInt8]()
    oid_rsa_sha256.append(UInt8(0x2A))
    oid_rsa_sha256.append(UInt8(0x86))
    oid_rsa_sha256.append(UInt8(0x48))
    oid_rsa_sha256.append(UInt8(0x86))
    oid_rsa_sha256.append(UInt8(0xF7))
    oid_rsa_sha256.append(UInt8(0x0D))
    oid_rsa_sha256.append(UInt8(0x01))
    oid_rsa_sha256.append(UInt8(0x01))
    oid_rsa_sha256.append(UInt8(0x0B))

    var oid_rsa_sha384 = List[UInt8]()
    oid_rsa_sha384.append(UInt8(0x2A))
    oid_rsa_sha384.append(UInt8(0x86))
    oid_rsa_sha384.append(UInt8(0x48))
    oid_rsa_sha384.append(UInt8(0x86))
    oid_rsa_sha384.append(UInt8(0xF7))
    oid_rsa_sha384.append(UInt8(0x0D))
    oid_rsa_sha384.append(UInt8(0x01))
    oid_rsa_sha384.append(UInt8(0x01))
    oid_rsa_sha384.append(UInt8(0x0C))

    if oid_equal(cert.signature_oid, oid_ecdsa_sha256):
        return verify_ecdsa_p256(cert.public_key, cert.tbs, cert.signature)
    if oid_equal(cert.signature_oid, oid_ecdsa_sha384):
        return verify_ecdsa_p384_hash(
            cert.public_key, sha384_bytes(cert.tbs), cert.signature
        )
    if oid_equal(cert.signature_oid, oid_rsa_sha256):
        return verify_rsa_pkcs1v15(cert.public_key, cert.tbs, cert.signature)
    if oid_equal(cert.signature_oid, oid_rsa_sha384):
        return verify_rsa_pkcs1v15(cert.public_key, cert.tbs, cert.signature)
    return False


fn verify_signature_with_issuer(
    cert: ParsedCertificate, issuer_pubkey: List[UInt8]
) raises -> Bool:
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

    var oid_rsa_sha256 = List[UInt8]()
    oid_rsa_sha256.append(UInt8(0x2A))
    oid_rsa_sha256.append(UInt8(0x86))
    oid_rsa_sha256.append(UInt8(0x48))
    oid_rsa_sha256.append(UInt8(0x86))
    oid_rsa_sha256.append(UInt8(0xF7))
    oid_rsa_sha256.append(UInt8(0x0D))
    oid_rsa_sha256.append(UInt8(0x01))
    oid_rsa_sha256.append(UInt8(0x01))
    oid_rsa_sha256.append(UInt8(0x0B))

    var oid_rsa_sha384 = List[UInt8]()
    oid_rsa_sha384.append(UInt8(0x2A))
    oid_rsa_sha384.append(UInt8(0x86))
    oid_rsa_sha384.append(UInt8(0x48))
    oid_rsa_sha384.append(UInt8(0x86))
    oid_rsa_sha384.append(UInt8(0xF7))
    oid_rsa_sha384.append(UInt8(0x0D))
    oid_rsa_sha384.append(UInt8(0x01))
    oid_rsa_sha384.append(UInt8(0x01))
    oid_rsa_sha384.append(UInt8(0x0C))

    if oid_equal(cert.signature_oid, oid_ecdsa_sha256):
        return verify_ecdsa_p256(issuer_pubkey, cert.tbs, cert.signature)
    if oid_equal(cert.signature_oid, oid_ecdsa_sha384):
        var h = sha384_bytes(cert.tbs)
        var ok = verify_ecdsa_p384_hash(issuer_pubkey, h, cert.signature)
        if not ok:
            print(
                "  ECDSA-SHA384 verification failed for "
                + to_string(cert.subject_cn)
            )
            print("  Issuer key len: " + String(len(issuer_pubkey)))
            print("  Signature len: " + String(len(cert.signature)))
        return ok
    if oid_equal(cert.signature_oid, oid_rsa_sha256):
        return verify_rsa_pkcs1v15(issuer_pubkey, cert.tbs, cert.signature)
    if oid_equal(cert.signature_oid, oid_rsa_sha384):
        return verify_rsa_pkcs1v15(issuer_pubkey, cert.tbs, cert.signature)
    return False


fn verify_chain(
    certs: List[List[UInt8]], trust: TrustStore, hostname: List[UInt8]
) raises -> Bool:
    if len(certs) == 0:
        return False
    var leaf_der = certs[0].copy()
    var leaf = parse_certificate(leaf_der)
    if len(leaf.tbs) == 0:
        return False
    if not hostname_matches(leaf, hostname):
        return False

    var current_cert = leaf.copy()
    var cert_idx = 0

    while True:
        # Check if current_cert is signed by any root
        for i in range(len(trust.roots)):
            var root = parse_certificate(trust.roots[i])
            if len(root.tbs) == 0:
                continue
            if bytes_equal(current_cert.issuer_cn, root.subject_cn):
                if verify_signature_with_issuer(current_cert, root.public_key):
                    return True

        # If not, check if signed by next intermediate in the provided list
        cert_idx += 1
        if cert_idx >= len(certs):
            break

        var next_cert = parse_certificate(certs[cert_idx])
        if bytes_equal(current_cert.issuer_cn, next_cert.subject_cn):
            if verify_signature_with_issuer(current_cert, next_cert.public_key):
                current_cert = next_cert.copy()
            else:
                return False
        else:
            return False

    return False
