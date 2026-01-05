"""Minimal TLS 1.3 client implementation (single cipher suite)."""
from collections import List

from lightbug_http.address import TCPAddr
from lightbug_http.io.bytes import Bytes
from memory import Span
from pki_instrumented.ecdsa_p256 import verify_ecdsa_p256_hash
from pki_instrumented.ecdsa_p384 import verify_ecdsa_p384_hash
from pki_instrumented.rsa import verify_rsa_pkcs1v15, verify_rsa_pss_sha256
from pki_instrumented.trust_store import load_trust_store
from pki_instrumented.x509 import parse_certificate, verify_chain

from crypto_instrumented.aes_gcm import aes_gcm_seal, aes_gcm_open
from crypto_instrumented.bytes import concat_bytes, zeros
from crypto_instrumented.hkdf import hkdf_extract, hkdf_expand
from crypto_instrumented.hmac import hmac_sha256
from crypto_instrumented.sha256 import sha256_bytes
from crypto_instrumented.sha384 import sha384_bytes
from crypto_instrumented.x25519 import x25519
from tls.transport import TLSTransport

alias TLS_VERSION = UInt16(0x0303)  # legacy_record_version
alias TLS13_VERSION = UInt16(0x0304)

alias CONTENT_HANDSHAKE = UInt8(22)
alias CONTENT_APPDATA = UInt8(23)
alias CONTENT_ALERT = UInt8(21)

alias HS_CLIENT_HELLO = UInt8(1)
alias HS_SERVER_HELLO = UInt8(2)
alias HS_ENCRYPTED_EXTENSIONS = UInt8(8)
alias HS_CERTIFICATE = UInt8(11)
alias HS_CERT_VERIFY = UInt8(15)
alias HS_FINISHED = UInt8(20)

alias EXT_SNI = UInt16(0x0000)
alias EXT_SUPPORTED_GROUPS = UInt16(0x000A)
alias EXT_SIG_ALGS = UInt16(0x000D)
alias EXT_SUPPORTED_VERSIONS = UInt16(0x002B)
alias EXT_PSK_MODES = UInt16(0x002D)
alias EXT_KEY_SHARE = UInt16(0x0033)

alias GROUP_X25519 = UInt16(0x001D)
alias CIPHER_TLS_AES_128_GCM_SHA256 = UInt16(0x1301)

alias SIG_RSA_PKCS1_SHA256 = UInt16(0x0401)
alias SIG_RSA_PKCS1_SHA384 = UInt16(0x0501)
alias SIG_RSA_PKCS1_SHA512 = UInt16(0x0601)
alias SIG_ECDSA_SECP256R1_SHA256 = UInt16(0x0403)
alias SIG_ECDSA_SECP384R1_SHA384 = UInt16(0x0503)
alias SIG_RSA_PSS_RSAE_SHA256 = UInt16(0x0804)


fn u16_to_bytes(v: UInt16) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8((v >> 8) & UInt16(0xFF)))
    out.append(UInt8(v & UInt16(0xFF)))
    return out^


fn u24_to_bytes(v: Int) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8((v >> 16) & 0xFF))
    out.append(UInt8((v >> 8) & 0xFF))
    out.append(UInt8(v & 0xFF))
    return out^


fn u32_to_bytes(v: UInt32) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8((v >> 24) & UInt32(0xFF)))
    out.append(UInt8((v >> 16) & UInt32(0xFF)))
    out.append(UInt8((v >> 8) & UInt32(0xFF)))
    out.append(UInt8(v & UInt32(0xFF)))
    return out^


fn bytes_to_u16(b: List[UInt8], idx: Int) -> UInt16:
    return (UInt16(b[idx]) << 8) | UInt16(b[idx + 1])


fn string_to_bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(UInt8(b))
    return out^


fn bytes_to_bytes(list: List[UInt8]) -> Bytes:
    var out = Bytes()
    for b in list:
        out.append(Byte(b))
    return out^


fn read_exact[
    T: TLSTransport
](mut transport: T, size: Int) raises -> List[UInt8]:
    var out = List[UInt8]()
    while len(out) < size:
        var buf = Bytes(capacity=size - len(out))
        var n = transport.read(buf)
        if n == 0:
            raise Error("TLS read_exact: unexpected EOF")
        var i = 0
        while i < n:
            out.append(UInt8(buf[i]))
            i += 1
    if len(out) > size:
        while len(out) > size:
            _ = out.pop()
    return out^


fn write_all[T: TLSTransport](mut transport: T, data: List[UInt8]) raises:
    var buf = bytes_to_bytes(data)
    _ = transport.write(Span(buf))


fn build_record(content_type: UInt8, payload: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(content_type)
    out.append(UInt8(0x03))
    out.append(UInt8(0x03))
    var len_bytes = u16_to_bytes(UInt16(len(payload)))
    out.append(len_bytes[0])
    out.append(len_bytes[1])
    for b in payload:
        out.append(b)
    return out^


fn hkdf_expand_label(
    secret: List[UInt8], label: String, context: List[UInt8], length: Int
) -> List[UInt8]:
    var full_label = "tls13 " + label
    var label_bytes = string_to_bytes(full_label)
    var info = List[UInt8]()
    var len_bytes = u16_to_bytes(UInt16(length))
    info.append(len_bytes[0])
    info.append(len_bytes[1])
    info.append(UInt8(len(label_bytes)))
    for b in label_bytes:
        info.append(b)
    info.append(UInt8(len(context)))
    for b in context:
        info.append(b)
    return hkdf_expand(secret, info, length)


fn derive_secret(
    secret: List[UInt8], label: String, transcript_hash: List[UInt8]
) -> List[UInt8]:
    return hkdf_expand_label(secret, label, transcript_hash, 32)


fn random_bytes(count: Int) -> List[UInt8]:
    var seed = UInt64(0x9E3779B97F4A7C15)
    var out = List[UInt8]()
    var i = 0
    while i < count:
        seed = seed * UInt64(6364136223846793005) + UInt64(1)
        out.append(UInt8((seed >> 24) & UInt64(0xFF)))
        i += 1
    return out^


struct ByteCursor:
    var data: List[UInt8]
    var pos: Int

    fn __init__(out self, data: List[UInt8]):
        self.data = data.copy()
        self.pos = 0

    fn remaining(self) -> Int:
        return len(self.data) - self.pos

    fn read_u8(mut self) raises -> UInt8:
        if self.pos >= len(self.data):
            raise Error("cursor: out of bounds")
        var v = self.data[self.pos]
        self.pos += 1
        return v

    fn read_u16(mut self) raises -> UInt16:
        var b0 = self.read_u8()
        var b1 = self.read_u8()
        return (UInt16(b0) << 8) | UInt16(b1)

    fn read_u24(mut self) raises -> Int:
        var b0 = Int(self.read_u8())
        var b1 = Int(self.read_u8())
        var b2 = Int(self.read_u8())
        return (b0 << 16) | (b1 << 8) | b2

    fn read_bytes(mut self, n: Int) raises -> List[UInt8]:
        if self.pos + n > len(self.data):
            raise Error("cursor: out of bounds")
        var out = List[UInt8]()
        var i = 0
        while i < n:
            out.append(self.data[self.pos + i])
            i += 1
        self.pos += n
        return out^


fn make_client_hello(
    host: String, client_random: List[UInt8], client_pub: List[UInt8]
) -> List[UInt8]:
    var body = List[UInt8]()
    body.append(UInt8(0x03))
    body.append(UInt8(0x03))  # legacy_version
    for b in client_random:
        body.append(b)
    body.append(UInt8(0))  # session id length
    var cipher_suites = List[UInt8]()
    var cs = u16_to_bytes(CIPHER_TLS_AES_128_GCM_SHA256)
    cipher_suites.append(cs[0])
    cipher_suites.append(cs[1])
    var cs_len = u16_to_bytes(UInt16(len(cipher_suites)))
    body.append(cs_len[0])
    body.append(cs_len[1])
    for b in cipher_suites:
        body.append(b)
    body.append(UInt8(1))  # compression methods length
    body.append(UInt8(0))

    var ext = List[UInt8]()
    # SNI
    var host_bytes = string_to_bytes(host)
    var sni_list = List[UInt8]()
    sni_list.append(UInt8(0))
    var host_len = u16_to_bytes(UInt16(len(host_bytes)))
    sni_list.append(host_len[0])
    sni_list.append(host_len[1])
    for b in host_bytes:
        sni_list.append(b)
    var sni_list_len = u16_to_bytes(UInt16(len(sni_list)))
    var sni = List[UInt8]()
    sni.append(sni_list_len[0])
    sni.append(sni_list_len[1])
    for b in sni_list:
        sni.append(b)
    var sni_len = u16_to_bytes(UInt16(len(sni)))
    var sni_ext = List[UInt8]()
    var sni_type = u16_to_bytes(EXT_SNI)
    sni_ext.append(sni_type[0])
    sni_ext.append(sni_type[1])
    sni_ext.append(sni_len[0])
    sni_ext.append(sni_len[1])
    for b in sni:
        sni_ext.append(b)
    for b in sni_ext:
        ext.append(b)

    # supported_versions
    var ver_list = List[UInt8]()
    ver_list.append(UInt8(2))
    ver_list.append(UInt8(0x03))
    ver_list.append(UInt8(0x04))
    var ver_len = u16_to_bytes(UInt16(len(ver_list)))
    var ver_ext = List[UInt8]()
    var ver_type = u16_to_bytes(EXT_SUPPORTED_VERSIONS)
    ver_ext.append(ver_type[0])
    ver_ext.append(ver_type[1])
    ver_ext.append(ver_len[0])
    ver_ext.append(ver_len[1])
    for b in ver_list:
        ver_ext.append(b)
    for b in ver_ext:
        ext.append(b)

    # supported_groups
    var groups = List[UInt8]()
    var g = u16_to_bytes(GROUP_X25519)
    groups.append(g[0])
    groups.append(g[1])
    var groups_len = u16_to_bytes(UInt16(len(groups)))
    var groups_data = List[UInt8]()
    groups_data.append(groups_len[0])
    groups_data.append(groups_len[1])
    for b in groups:
        groups_data.append(b)
    var groups_data_len = u16_to_bytes(UInt16(len(groups_data)))
    var groups_ext = List[UInt8]()
    var groups_type = u16_to_bytes(EXT_SUPPORTED_GROUPS)
    groups_ext.append(groups_type[0])
    groups_ext.append(groups_type[1])
    groups_ext.append(groups_data_len[0])
    groups_ext.append(groups_data_len[1])
    for b in groups_data:
        groups_ext.append(b)
    for b in groups_ext:
        ext.append(b)

    # signature_algorithms
    var sigs = List[UInt8]()
    var s1 = u16_to_bytes(SIG_ECDSA_SECP256R1_SHA256)
    var s2 = u16_to_bytes(SIG_ECDSA_SECP384R1_SHA384)
    var s3 = u16_to_bytes(SIG_RSA_PSS_RSAE_SHA256)
    var s4 = u16_to_bytes(SIG_RSA_PKCS1_SHA256)
    var s5 = u16_to_bytes(SIG_RSA_PKCS1_SHA384)
    sigs.append(s1[0])
    sigs.append(s1[1])
    sigs.append(s2[0])
    sigs.append(s2[1])
    sigs.append(s3[0])
    sigs.append(s3[1])
    sigs.append(s4[0])
    sigs.append(s4[1])
    sigs.append(s5[0])
    sigs.append(s5[1])
    var sigs_len = u16_to_bytes(UInt16(len(sigs)))
    var sigs_data = List[UInt8]()
    sigs_data.append(sigs_len[0])
    sigs_data.append(sigs_len[1])
    for b in sigs:
        sigs_data.append(b)
    var sigs_data_len = u16_to_bytes(UInt16(len(sigs_data)))
    var sigs_ext = List[UInt8]()
    var sigs_type = u16_to_bytes(EXT_SIG_ALGS)
    sigs_ext.append(sigs_type[0])
    sigs_ext.append(sigs_type[1])
    sigs_ext.append(sigs_data_len[0])
    sigs_ext.append(sigs_data_len[1])
    for b in sigs_data:
        sigs_ext.append(b)
    for b in sigs_ext:
        ext.append(b)

    # key_share
    var ks_entry = List[UInt8]()
    var grp = u16_to_bytes(GROUP_X25519)
    ks_entry.append(grp[0])
    ks_entry.append(grp[1])
    var klen = u16_to_bytes(UInt16(len(client_pub)))
    ks_entry.append(klen[0])
    ks_entry.append(klen[1])
    for b in client_pub:
        ks_entry.append(b)
    var ks_list_len = u16_to_bytes(UInt16(len(ks_entry)))
    var ks_data = List[UInt8]()
    ks_data.append(ks_list_len[0])
    ks_data.append(ks_list_len[1])
    for b in ks_entry:
        ks_data.append(b)
    var ks_data_len = u16_to_bytes(UInt16(len(ks_data)))
    var ks_ext = List[UInt8]()
    var ks_type = u16_to_bytes(EXT_KEY_SHARE)
    ks_ext.append(ks_type[0])
    ks_ext.append(ks_type[1])
    ks_ext.append(ks_data_len[0])
    ks_ext.append(ks_data_len[1])
    for b in ks_data:
        ks_ext.append(b)
    for b in ks_ext:
        ext.append(b)

    var ext_len = u16_to_bytes(UInt16(len(ext)))
    body.append(ext_len[0])
    body.append(ext_len[1])
    for b in ext:
        body.append(b)
    return body^


fn wrap_handshake(msg_type: UInt8, body: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(msg_type)
    var len_bytes = u24_to_bytes(len(body))
    out.append(len_bytes[0])
    out.append(len_bytes[1])
    out.append(len_bytes[2])
    for b in body:
        out.append(b)
    return out^


fn build_tls_inner_plaintext(
    content: List[UInt8], content_type: UInt8
) -> List[UInt8]:
    var out = List[UInt8]()
    for b in content:
        out.append(b)
    out.append(content_type)
    return out^


fn build_record_aad(length: Int) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8(CONTENT_APPDATA))
    out.append(UInt8(0x03))
    out.append(UInt8(0x03))
    var len_bytes = u16_to_bytes(UInt16(length))
    out.append(len_bytes[0])
    out.append(len_bytes[1])
    return out^


struct TLS13Keys(Movable):
    var client_hs_secret: List[UInt8]
    var server_hs_secret: List[UInt8]
    var client_hs_key: List[UInt8]
    var server_hs_key: List[UInt8]
    var client_hs_iv: List[UInt8]
    var server_hs_iv: List[UInt8]
    var client_finished_key: List[UInt8]
    var server_finished_key: List[UInt8]

    var client_app_secret: List[UInt8]
    var server_app_secret: List[UInt8]
    var client_app_key: List[UInt8]
    var server_app_key: List[UInt8]
    var client_app_iv: List[UInt8]
    var server_app_iv: List[UInt8]

    fn __init__(out self):
        self.client_hs_secret = List[UInt8]()
        self.server_hs_secret = List[UInt8]()
        self.client_hs_key = List[UInt8]()
        self.server_hs_key = List[UInt8]()
        self.client_hs_iv = List[UInt8]()
        self.server_hs_iv = List[UInt8]()
        self.client_finished_key = List[UInt8]()
        self.server_finished_key = List[UInt8]()
        self.client_app_secret = List[UInt8]()
        self.server_app_secret = List[UInt8]()
        self.client_app_key = List[UInt8]()
        self.server_app_key = List[UInt8]()
        self.client_app_iv = List[UInt8]()
        self.server_app_iv = List[UInt8]()


struct TLS13Client[T: TLSTransport](Movable):
    var transport: T
    var host: String
    var transcript: List[UInt8]
    var keys: TLS13Keys
    var handshake_secret: List[UInt8]
    var shared_secret: List[UInt8]
    var server_pubkey: List[UInt8]
    var seq_out: UInt64
    var seq_in: UInt64
    var app_seq_out: UInt64
    var app_seq_in: UInt64
    var handshake_done: Bool

    fn __init__(out self, var transport: T, host: String):
        self.transport = transport^
        self.host = host
        self.transcript = List[UInt8]()
        self.keys = TLS13Keys()
        self.handshake_secret = List[UInt8]()
        self.shared_secret = List[UInt8]()
        self.server_pubkey = List[UInt8]()
        self.seq_out = UInt64(0)
        self.seq_in = UInt64(0)
        self.app_seq_out = UInt64(0)
        self.app_seq_in = UInt64(0)
        self.handshake_done = False

    fn record_nonce(self, iv: List[UInt8], seq: UInt64) -> List[UInt8]:
        var out = List[UInt8]()
        for b in iv:
            out.append(b)
        var seq_bytes = List[UInt8]()
        var i = 0
        while i < 8:
            var shift = (7 - i) * 8
            seq_bytes.append(UInt8((seq >> shift) & UInt64(0xFF)))
            i += 1
        i = 0
        while i < 8:
            var idx = 4 + i
            out[idx] = UInt8(out[idx] ^ seq_bytes[i])
            i += 1
        return out^

    fn encrypt_record(
        mut self,
        plaintext: List[UInt8],
        content_type: UInt8,
        key: List[UInt8],
        iv: List[UInt8],
        seq: UInt64,
    ) -> List[UInt8]:
        var inner = build_tls_inner_plaintext(plaintext, content_type)
        var nonce = self.record_nonce(iv, seq)
        var aad = build_record_aad(len(inner) + 16)
        var sealed = aes_gcm_seal(key, nonce, aad, inner)
        var out = List[UInt8]()
        for b in sealed[0]:
            out.append(b)
        for b in sealed[1]:
            out.append(b)
        return build_record(CONTENT_APPDATA, out)

    fn decrypt_record(
        self,
        ciphertext: List[UInt8],
        key: List[UInt8],
        iv: List[UInt8],
        seq: UInt64,
    ) raises -> (List[UInt8], UInt8):
        if len(ciphertext) < 16:
            raise Error("TLS decrypt: ciphertext too short")
        var ct = List[UInt8]()
        var tag = List[UInt8]()
        var i = 0
        while i < len(ciphertext) - 16:
            ct.append(ciphertext[i])
            i += 1
        while i < len(ciphertext):
            tag.append(ciphertext[i])
            i += 1
        var aad = build_record_aad(len(ciphertext))
        var nonce = self.record_nonce(iv, seq)
        var opened = aes_gcm_open(key, nonce, aad, ct, tag)
        if not opened[1]:
            raise Error("TLS decrypt: auth failed")
        var inner = opened[0].copy()
        var idx = len(inner) - 1
        while idx >= 0 and inner[idx] == UInt8(0):
            idx -= 1
        if idx < 0:
            raise Error("TLS decrypt: no content type")
        var content_type = inner[idx]
        var content = List[UInt8]()
        var j = 0
        while j < idx:
            content.append(inner[j])
            j += 1
        return (content^, content_type)

    fn read_record(mut self) raises -> (UInt8, List[UInt8]):
        var header = read_exact(self.transport, 5)
        var content_type = header[0]
        var length = Int(bytes_to_u16(header, 3))
        var payload = read_exact(self.transport, length)
        return (content_type, payload^)

    fn send_handshake(
        mut self, handshake_msg: List[UInt8], encrypt: Bool
    ) raises:
        if encrypt:
            var key = self.keys.client_hs_key.copy()
            var iv = self.keys.client_hs_iv.copy()
            var record = self.encrypt_record(
                handshake_msg, CONTENT_HANDSHAKE, key, iv, self.seq_out
            )
            self.seq_out += UInt64(1)
            write_all(self.transport, record)
        else:
            var record = build_record(CONTENT_HANDSHAKE, handshake_msg)
            write_all(self.transport, record)

    fn perform_handshake(mut self) raises -> Bool:
        var client_random = random_bytes(32)
        var client_priv = random_bytes(32)
        var base_u = List[UInt8]()
        base_u.append(UInt8(9))
        var i = 1
        while i < 32:
            base_u.append(UInt8(0))
            i += 1
        var client_pub = x25519(client_priv, base_u)

        var ch_body = make_client_hello(self.host, client_random, client_pub)
        var ch_msg = wrap_handshake(HS_CLIENT_HELLO, ch_body)
        for b in ch_msg:
            self.transcript.append(b)
        self.send_handshake(ch_msg, False)

        var rec = self.read_record()
        if rec[0] == CONTENT_ALERT:
            var level = rec[1][0]
            var desc = rec[1][1]
            raise Error(
                "TLS handshake: received alert "
                + String(desc)
                + " (level "
                + String(level)
                + ")"
            )
        if rec[0] != CONTENT_HANDSHAKE:
            raise Error(
                "TLS handshake: expected ServerHello record, got "
                + String(rec[0])
            )
        var cursor = ByteCursor(rec[1])
        var msg_type = cursor.read_u8()
        if msg_type != HS_SERVER_HELLO:
            raise Error("TLS handshake: expected ServerHello message")
        var msg_len = cursor.read_u24()
        var sh_body = cursor.read_bytes(msg_len)
        var sh_msg = wrap_handshake(msg_type, sh_body)
        for b in sh_msg:
            self.transcript.append(b)

        # parse ServerHello
        var sh = ByteCursor(sh_body)
        _ = sh.read_u16()  # legacy_version
        var server_random = sh.read_bytes(32)
        var hrr = List[UInt8]()
        var hrr_hex = (
            "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
        )
        var i_hrr = 0
        while i_hrr < len(hrr_hex):
            var hi = hrr_hex[i_hrr]
            var lo = hrr_hex[i_hrr + 1]
            var byte_val = UInt8(0)
            if hi >= "0" and hi <= "9":
                byte_val = UInt8((ord(hi) - ord("0")) << 4)
            elif hi >= "a" and hi <= "f":
                byte_val = UInt8((10 + ord(hi) - ord("a")) << 4)
            if lo >= "0" and lo <= "9":
                byte_val |= UInt8(ord(lo) - ord("0"))
            elif lo >= "a" and lo <= "f":
                byte_val |= UInt8(10 + ord(lo) - ord("a"))
            hrr.append(byte_val)
            i_hrr += 2
        var is_hrr = True
        var idx_hrr = 0
        while idx_hrr < 32:
            if server_random[idx_hrr] != hrr[idx_hrr]:
                is_hrr = False
                break
            idx_hrr += 1
        if is_hrr:
            raise Error("TLS handshake: HelloRetryRequest not supported")
        var sid_len = Int(sh.read_u8())
        if sid_len > 0:
            _ = sh.read_bytes(sid_len)
        var cipher = sh.read_u16()
        if cipher != CIPHER_TLS_AES_128_GCM_SHA256:
            raise Error("TLS handshake: unsupported cipher suite")
        _ = sh.read_u8()  # compression
        var ext_len = Int(sh.read_u16())
        var ext_bytes = sh.read_bytes(ext_len)
        var ext_cur = ByteCursor(ext_bytes)
        var server_pub = List[UInt8]()
        while ext_cur.remaining() > 0:
            var etype = ext_cur.read_u16()
            var elen = Int(ext_cur.read_u16())
            var edata = ext_cur.read_bytes(elen)
            if etype == EXT_KEY_SHARE:
                var ec = ByteCursor(edata)
                var group = ec.read_u16()
                var klen = Int(ec.read_u16())
                if group == GROUP_X25519:
                    server_pub = ec.read_bytes(klen)
            elif etype == EXT_SUPPORTED_VERSIONS:
                var ec2 = ByteCursor(edata)
                var ver = ec2.read_u16()
                if ver != TLS13_VERSION:
                    raise Error("TLS handshake: server negotiated non-TLS1.3")
        if len(server_pub) != 32:
            raise Error("TLS handshake: missing X25519 key share")

        var shared = x25519(client_priv, server_pub)
        var empty = List[UInt8]()
        var zeros32 = zeros(32)
        var empty_hash = sha256_bytes(empty)
        var early = hkdf_extract(empty, zeros32)
        var derived = hkdf_expand_label(early, "derived", empty_hash, 32)
        var handshake_secret = hkdf_extract(derived, shared)
        self.handshake_secret = handshake_secret.copy()
        self.shared_secret = shared.copy()
        var th = sha256_bytes(self.transcript)
        self.keys.client_hs_secret = hkdf_expand_label(
            handshake_secret, "c hs traffic", th, 32
        )
        self.keys.server_hs_secret = hkdf_expand_label(
            handshake_secret, "s hs traffic", th, 32
        )
        self.keys.client_hs_key = hkdf_expand_label(
            self.keys.client_hs_secret, "key", List[UInt8](), 16
        )
        self.keys.server_hs_key = hkdf_expand_label(
            self.keys.server_hs_secret, "key", List[UInt8](), 16
        )
        self.keys.client_hs_iv = hkdf_expand_label(
            self.keys.client_hs_secret, "iv", List[UInt8](), 12
        )
        self.keys.server_hs_iv = hkdf_expand_label(
            self.keys.server_hs_secret, "iv", List[UInt8](), 12
        )
        self.keys.client_finished_key = hkdf_expand_label(
            self.keys.client_hs_secret, "finished", List[UInt8](), 32
        )
        self.keys.server_finished_key = hkdf_expand_label(
            self.keys.server_hs_secret, "finished", List[UInt8](), 32
        )

        # read encrypted handshake messages
        var handshake_buf = List[UInt8]()
        var got_finished = False
        while not got_finished:
            var rec2 = self.read_record()
            if rec2[0] == CONTENT_ALERT:
                raise Error("TLS handshake: received alert during handshake")
            if rec2[0] != CONTENT_APPDATA:
                continue
            var dec = self.decrypt_record(
                rec2[1],
                self.keys.server_hs_key,
                self.keys.server_hs_iv,
                self.seq_in,
            )
            self.seq_in += UInt64(1)
            if dec[1] != CONTENT_HANDSHAKE:
                continue
            for b in dec[0]:
                handshake_buf.append(b)
            var hc = ByteCursor(handshake_buf)
            var consumed = 0
            while hc.remaining() >= 4:
                var mt = hc.read_u8()
                var ml = hc.read_u24()
                if hc.remaining() < ml:
                    hc.pos -= 4
                    break
                var body = hc.read_bytes(ml)
                var full = wrap_handshake(mt, body)
                consumed = hc.pos
                if mt == HS_CERTIFICATE:
                    for b in full:
                        self.transcript.append(b)
                    var cert_cur = ByteCursor(body)
                    var ctx_len = Int(cert_cur.read_u8())
                    if ctx_len > 0:
                        _ = cert_cur.read_bytes(ctx_len)
                    var list_len = cert_cur.read_u24()
                    var list_bytes = cert_cur.read_bytes(list_len)
                    var list_cur = ByteCursor(list_bytes)

                    var cert_list = List[List[UInt8]]()
                    while list_cur.remaining() > 0:
                        var cert_len = list_cur.read_u24()
                        var cert_der = list_cur.read_bytes(cert_len)
                        cert_list.append(cert_der^)
                        # Extensions for each cert
                        var ext_len_cert = Int(list_cur.read_u16())
                        if ext_len_cert > 0:
                            _ = list_cur.read_bytes(ext_len_cert)

                    print(
                        "  Received "
                        + String(len(cert_list))
                        + " certificates from server"
                    )
                    if len(cert_list) > 0:
                        var leaf_der = cert_list[0].copy()
                        var parsed = parse_certificate(leaf_der)
                        self.server_pubkey = parsed.public_key.copy()
                        var trust = load_trust_store()
                        var host_bytes = string_to_bytes(self.host)
                        if not verify_chain(cert_list, trust, host_bytes):
                            raise Error(
                                "TLS handshake: certificate verification failed"
                            )
                elif mt == HS_CERT_VERIFY:
                    var cv = ByteCursor(body)
                    var sig_alg = cv.read_u16()
                    var sig_len = Int(cv.read_u16())
                    var sig = cv.read_bytes(sig_len)
                    var context = "TLS 1.3, server CertificateVerify"
                    var prefix = List[UInt8]()
                    var i2 = 0
                    while i2 < 64:
                        prefix.append(UInt8(0x20))
                        i2 += 1
                    var ctx_bytes = string_to_bytes(context)
                    var signed = List[UInt8]()
                    for b in prefix:
                        signed.append(b)
                    for b in ctx_bytes:
                        signed.append(b)
                    signed.append(UInt8(0x00))
                    var thash = sha256_bytes(self.transcript)
                    if (
                        sig_alg == SIG_ECDSA_SECP384R1_SHA384
                        or sig_alg == SIG_RSA_PKCS1_SHA384
                    ):
                        thash = sha384_bytes(self.transcript)
                    for b in thash:
                        signed.append(b)
                    if len(self.server_pubkey) == 0:
                        raise Error("TLS handshake: missing server public key")
                    var sig_hash = sha256_bytes(signed)
                    if (
                        sig_alg == SIG_ECDSA_SECP384R1_SHA384
                        or sig_alg == SIG_RSA_PKCS1_SHA384
                    ):
                        sig_hash = sha384_bytes(signed)

                    var verified: Bool
                    if sig_alg == SIG_RSA_PSS_RSAE_SHA256:
                        verified = verify_rsa_pss_sha256(
                            self.server_pubkey, signed, sig
                        )
                    elif (
                        sig_alg == SIG_RSA_PKCS1_SHA256
                        or sig_alg == SIG_RSA_PKCS1_SHA384
                    ):
                        verified = verify_rsa_pkcs1v15(
                            self.server_pubkey, signed, sig
                        )
                    elif sig_alg == SIG_ECDSA_SECP384R1_SHA384:
                        verified = verify_ecdsa_p384_hash(
                            self.server_pubkey, sig_hash, sig
                        )
                    else:
                        verified = verify_ecdsa_p256_hash(
                            self.server_pubkey, sig_hash, sig
                        )

                    if not verified:
                        raise Error("TLS handshake: CertificateVerify failed")
                    for b in full:
                        self.transcript.append(b)
                elif mt == HS_FINISHED:
                    var th2 = sha256_bytes(self.transcript)
                    var expected = hmac_sha256(
                        self.keys.server_finished_key, th2
                    )
                    if len(body) != len(expected):
                        raise Error("TLS handshake: Finished length mismatch")
                    var ok = True
                    var i3 = 0
                    while i3 < len(expected):
                        if body[i3] != expected[i3]:
                            ok = False
                        i3 += 1
                    if not ok:
                        raise Error("TLS handshake: Finished verify failed")
                    got_finished = True
                    for b in full:
                        self.transcript.append(b)
                    break
                else:
                    for b in full:
                        self.transcript.append(b)
            if consumed > 0:
                var remaining = List[UInt8]()
                var i4 = consumed
                while i4 < len(handshake_buf):
                    remaining.append(handshake_buf[i4])
                    i4 += 1
                handshake_buf = remaining^

        # derive application keys and send client Finished
        var th3 = sha256_bytes(self.transcript)
        var derived2 = hkdf_expand_label(
            self.handshake_secret, "derived", empty_hash, 32
        )
        var master = hkdf_extract(derived2, zeros32)
        self.keys.client_app_secret = hkdf_expand_label(
            master, "c ap traffic", th3, 32
        )
        self.keys.server_app_secret = hkdf_expand_label(
            master, "s ap traffic", th3, 32
        )
        var finished = hmac_sha256(self.keys.client_finished_key, th3)
        var fin_msg = wrap_handshake(HS_FINISHED, finished)
        for b in fin_msg:
            self.transcript.append(b)
        self.send_handshake(fin_msg, True)
        self.keys.client_app_key = hkdf_expand_label(
            self.keys.client_app_secret, "key", List[UInt8](), 16
        )
        self.keys.server_app_key = hkdf_expand_label(
            self.keys.server_app_secret, "key", List[UInt8](), 16
        )
        self.keys.client_app_iv = hkdf_expand_label(
            self.keys.client_app_secret, "iv", List[UInt8](), 12
        )
        self.keys.server_app_iv = hkdf_expand_label(
            self.keys.server_app_secret, "iv", List[UInt8](), 12
        )
        self.handshake_done = True
        return True

    fn write_app_data(mut self, plaintext: List[UInt8]) raises:
        if not self.handshake_done:
            raise Error("TLS: handshake not complete")
        var key = self.keys.client_app_key.copy()
        var iv = self.keys.client_app_iv.copy()
        var record = self.encrypt_record(
            plaintext, CONTENT_APPDATA, key, iv, self.app_seq_out
        )
        self.app_seq_out += UInt64(1)
        write_all(self.transport, record)

    fn read_app_data(mut self) raises -> List[UInt8]:
        if not self.handshake_done:
            raise Error("TLS: handshake not complete")
        while True:
            var rec = self.read_record()
            if rec[0] != CONTENT_APPDATA:
                continue
            var dec = self.decrypt_record(
                rec[1],
                self.keys.server_app_key,
                self.keys.server_app_iv,
                self.app_seq_in,
            )
            self.app_seq_in += UInt64(1)
            if dec[1] == CONTENT_APPDATA:
                return dec[0].copy()
