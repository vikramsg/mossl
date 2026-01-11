"""TLS 1.3 implementation for Mojo.
Focuses on safe, non-allocating cryptographic operations.
"""

from collections import List, InlineArray

from lightbug_http.io.bytes import Bytes
from memory import Span
from pki.ecdsa_p256 import verify_ecdsa_p256_hash
from pki.ecdsa_p384 import verify_ecdsa_p384_hash
from pki.rsa import verify_rsa_pkcs1v15, verify_rsa_pss_sha256
from pki.trust_store import load_trust_store
from pki.x509 import parse_certificate, verify_chain

from crypto.aes_gcm import aes_gcm_seal_internal, aes_gcm_open_internal
from crypto.bytes import zeros
from crypto.hkdf import hkdf_extract, hkdf_expand
from crypto.hmac import hmac_sha256
from crypto.sha256 import sha256
from crypto.x25519 import x25519
from tls.transport import TLSTransport

alias TLS_VERSION = UInt16(0x0303)
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
alias HS_KEY_UPDATE = UInt8(24)

alias EXT_SNI = UInt16(0x0000)
alias EXT_SUPPORTED_GROUPS = UInt16(0x000A)
alias EXT_SIG_ALGS = UInt16(0x000D)
alias EXT_SUPPORTED_VERSIONS = UInt16(0x002B)
alias EXT_PSK_MODES = UInt16(0x002D)
alias EXT_KEY_SHARE = UInt16(0x0033)

alias GROUP_X25519 = UInt16(0x001D)
alias CIPHER_TLS_AES_128_GCM_SHA256 = UInt16(0x1301)
alias CIPHER_TLS_AES_256_GCM_SHA384 = UInt16(0x1302)
alias CIPHER_TLS_CHACHA20_POLY1305_SHA256 = UInt16(0x1303)

alias SIG_RSA_PKCS1_SHA256 = UInt16(0x0401)
alias SIG_RSA_PKCS1_SHA384 = UInt16(0x0501)
alias SIG_RSA_PKCS1_SHA512 = UInt16(0x0601)
alias SIG_ECDSA_SECP256R1_SHA256 = UInt16(0x0403)
alias SIG_ECDSA_SECP384R1_SHA384 = UInt16(0x0503)
alias SIG_RSA_PSS_RSAE_SHA256 = UInt16(0x0804)


@fieldwise_init
struct HandshakeMessage(Movable):
    """A TLS handshake message."""

    var msg_type: UInt8
    var payload: List[UInt8]

    fn __moveinit__(out self, deinit other: Self):
        self.msg_type = other.msg_type
        self.payload = other.payload^


@fieldwise_init
struct HandshakeDefragmenter(Movable):
    """Helper for reading sequential handshake messages from TLS records."""

    var buffer: List[UInt8]

    fn __moveinit__(out self, deinit other: Self):
        self.buffer = other.buffer^

    fn __init__(out self):
        self.buffer = List[UInt8]()

    fn add_data(mut self, data: List[UInt8]):
        """Adds raw decrypted record content to the buffer."""
        self.buffer.extend(data.copy())

    fn has_full_message(self) -> Bool:
        """Checks if at least one full message is in the buffer."""
        if len(self.buffer) < 4:
            return False
        var length = (
            (Int(self.buffer[1]) << 16)
            | (Int(self.buffer[2]) << 8)
            | Int(self.buffer[3])
        )
        return len(self.buffer) >= 4 + length

    fn next_message(mut self) raises -> HandshakeMessage:
        """Parses and returns the next handshake message from the buffer."""
        if len(self.buffer) < 4:
            raise Error("Handshake reader: no message header")

        var msg_type = self.buffer[0]
        var length = (
            (Int(self.buffer[1]) << 16)
            | (Int(self.buffer[2]) << 8)
            | Int(self.buffer[3])
        )

        if len(self.buffer) < 4 + length:
            raise Error("Handshake reader: message incomplete")

        var payload = List[UInt8](capacity=length)
        for i in range(length):
            payload.append(self.buffer[4 + i])

        # Remove consumed bytes from buffer efficiently
        var new_buffer = List[UInt8](capacity=len(self.buffer) - (4 + length))
        for i in range(4 + length, len(self.buffer)):
            new_buffer.append(self.buffer[i])
        self.buffer = new_buffer^

        return HandshakeMessage(msg_type, payload^)


struct ByteCursor:
    """Helper for reading sequential values from a byte buffer."""

    var data: List[UInt8]
    var pos: Int

    fn __init__(out self, data: List[UInt8]):
        self.data = data.copy()
        self.pos = 0

    fn remaining(self) -> Int:
        """Returns the number of bytes remaining in the buffer."""
        return len(self.data) - self.pos

    fn read_u8(mut self) raises -> UInt8:
        """Reads a single byte."""
        if self.pos >= len(self.data):
            raise Error("cursor: out of bounds")
        var v = self.data[self.pos]
        self.pos += 1
        return v

    fn read_u16(mut self) raises -> UInt16:
        """Reads a 16-bit big-endian unsigned integer."""
        var b0 = self.read_u8()
        var b1 = self.read_u8()
        return (UInt16(b0) << 8) | UInt16(b1)

    fn read_u24(mut self) raises -> Int:
        """Reads a 24-bit big-endian unsigned integer."""
        var b0 = Int(self.read_u8())
        var b1 = Int(self.read_u8())
        var b2 = Int(self.read_u8())
        return (b0 << 16) | (b1 << 8) | b2

    fn read_bytes(mut self, n: Int) raises -> List[UInt8]:
        """Reads n bytes into a new list."""
        if self.pos + n > len(self.data):
            raise Error("cursor: out of bounds")
        var out = List[UInt8]()
        var i = 0
        while i < n:
            out.append(self.data[self.pos + i])
            i += 1
        self.pos += n
        return out^


struct TLS13Keys(Copyable, ImplicitlyCopyable):
    """Container for TLS 1.3 session keys and secrets."""

    var client_hs_secret: List[UInt8]
    var server_hs_secret: List[UInt8]
    var client_hs_key: List[UInt8]
    var server_hs_key: List[UInt8]
    var client_hs_iv: InlineArray[UInt8, 12]
    var server_hs_iv: InlineArray[UInt8, 12]
    var client_finished_key: List[UInt8]
    var server_finished_key: List[UInt8]

    var client_app_secret: List[UInt8]
    var server_app_secret: List[UInt8]
    var client_app_key: List[UInt8]
    var server_app_key: List[UInt8]
    var client_app_iv: InlineArray[UInt8, 12]
    var server_app_iv: InlineArray[UInt8, 12]

    fn __init__(out self):
        self.client_hs_secret = List[UInt8]()
        self.server_hs_secret = List[UInt8]()
        self.client_hs_key = List[UInt8]()
        self.server_hs_key = List[UInt8]()
        self.client_hs_iv = InlineArray[UInt8, 12](0)
        self.server_hs_iv = InlineArray[UInt8, 12](0)
        self.client_finished_key = List[UInt8]()
        self.server_finished_key = List[UInt8]()
        self.client_app_secret = List[UInt8]()
        self.server_app_secret = List[UInt8]()
        self.client_app_key = List[UInt8]()
        self.server_app_key = List[UInt8]()
        self.client_app_iv = InlineArray[UInt8, 12](0)
        self.server_app_iv = InlineArray[UInt8, 12](0)

    fn __copyinit__(out self, other: Self):
        self.client_hs_secret = other.client_hs_secret.copy()
        self.server_hs_secret = other.server_hs_secret.copy()
        self.client_hs_key = other.client_hs_key.copy()
        self.server_hs_key = other.server_hs_key.copy()
        self.client_hs_iv = other.client_hs_iv
        self.server_hs_iv = other.server_hs_iv
        self.client_finished_key = other.client_finished_key.copy()
        self.server_finished_key = other.server_finished_key.copy()
        self.client_app_secret = other.client_app_secret.copy()
        self.server_app_secret = other.server_app_secret.copy()
        self.client_app_key = other.client_app_key.copy()
        self.server_app_key = other.server_app_key.copy()
        self.client_app_iv = other.client_app_iv
        self.server_app_iv = other.server_app_iv


@fieldwise_init
struct TLSRecord(Movable):
    """A raw TLS record."""

    var content_type: UInt8
    var payload: List[UInt8]

    fn __moveinit__(out self, deinit other: Self):
        self.content_type = other.content_type
        self.payload = other.payload^


@fieldwise_init
struct DecryptedRecord(Movable):
    """A decrypted TLS record's inner content."""

    var content: List[UInt8]
    var inner_type: UInt8

    fn __moveinit__(out self, deinit other: Self):
        self.content = other.content^
        self.inner_type = other.inner_type


fn u16_to_bytes(v: UInt16) -> InlineArray[UInt8, 2]:
    """Converts a 16-bit unsigned integer to big-endian bytes (Public API)."""
    return _u16_to_bytes(v)


fn _u16_to_bytes(v: UInt16) -> InlineArray[UInt8, 2]:
    """Converts a 16-bit unsigned integer to big-endian bytes."""
    return InlineArray[UInt8, 2](UInt8(v >> 8), UInt8(v & 0xFF))


fn _u24_to_bytes(v: Int) -> InlineArray[UInt8, 3]:
    """Converts a 24-bit integer to big-endian bytes."""
    return InlineArray[UInt8, 3](
        UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)
    )


fn _bytes_to_u16(b: List[UInt8], idx: Int) -> UInt16:
    """Reads a 16-bit big-endian unsigned integer from a byte buffer."""
    return (UInt16(b[idx]) << 8) | UInt16(b[idx + 1])


fn _string_to_bytes(s: String) -> List[UInt8]:
    """Converts a string to a byte list."""
    var out = List[UInt8](capacity=len(s))
    for b in s.as_bytes():
        out.append(UInt8(b))
    return out^


fn _wrap_handshake(msg_type: UInt8, body: List[UInt8]) -> List[UInt8]:
    """Wraps a handshake message with type and length header."""
    var out = List[UInt8](capacity=4 + len(body))
    out.append(msg_type)
    var lb = _u24_to_bytes(len(body))
    out.append(lb[0])
    out.append(lb[1])
    out.append(lb[2])
    for b in body:
        out.append(b)
    return out^


fn random_bytes(n: Int) raises -> List[UInt8]:
    """Generates n random bytes using OS source (Public API)."""
    return _random_bytes(n)


fn _random_bytes(n: Int) raises -> List[UInt8]:
    """Reads secure random bytes from /dev/urandom."""
    with open("/dev/urandom", "r") as f:
        return f.read_bytes(n)


fn _read_exact[
    T: TLSTransport
](mut transport: T, size: Int) raises -> List[UInt8]:
    """Reads exactly N bytes from the transport."""
    var out = List[UInt8](capacity=size)
    while len(out) < size:
        var remaining = size - len(out)
        var buf = Bytes(capacity=remaining)
        var n = transport.read(buf)
        if n == 0:
            raise Error("TLS read_exact: unexpected EOF")
        var to_copy = n
        if to_copy > remaining:
            to_copy = remaining
        for i in range(to_copy):
            out.append(UInt8(buf[i]))
    return out^


fn _tls13_hkdf_expand_label[
    target_len: Int
](
    secret: Span[UInt8], label: String, context: Span[UInt8]
) raises -> InlineArray[UInt8, target_len]:
    """Performs HKDF-Expand-Label as defined in TLS 1.3."""
    var full_label = "tls13 " + label
    var label_bytes = _string_to_bytes(full_label)
    var info = List[UInt8](capacity=2 + 1 + len(label_bytes) + 1 + len(context))
    var len_bytes = _u16_to_bytes(UInt16(target_len))
    info.append(len_bytes[0])
    info.append(len_bytes[1])
    info.append(UInt8(len(label_bytes)))
    for b in label_bytes:
        info.append(b)
    info.append(UInt8(len(context)))
    for i in range(len(context)):
        info.append(context[i])

    var tmp = hkdf_expand(secret, info, target_len)
    var out = InlineArray[UInt8, target_len](0)
    for i in range(target_len):
        out[i] = tmp[i]
    return out


fn _tls13_hkdf_expand_label_sha384[
    target_len: Int
](
    secret: Span[UInt8], label: String, context: Span[UInt8]
) raises -> InlineArray[UInt8, target_len]:
    """Performs HKDF-Expand-Label using SHA-384."""
    var full_label = "tls13 " + label
    var label_bytes = _string_to_bytes(full_label)
    var info = List[UInt8](capacity=2 + 1 + len(label_bytes) + 1 + len(context))
    var len_bytes = _u16_to_bytes(UInt16(target_len))
    info.append(len_bytes[0])
    info.append(len_bytes[1])
    info.append(UInt8(len(label_bytes)))
    for b in label_bytes:
        info.append(b)
    info.append(UInt8(len(context)))
    for i in range(len(context)):
        info.append(context[i])

    from crypto.hkdf import hkdf_expand_sha384

    var tmp = hkdf_expand_sha384(secret, info, target_len)
    var out = InlineArray[UInt8, target_len](0)
    for i in range(target_len):
        out[i] = tmp[i]
    return out


fn hkdf_expand_label(
    secret: List[UInt8], label: String, context: List[UInt8], length: Int
) raises -> List[UInt8]:
    """Public wrapper for HKDF-Expand-Label returning List[UInt8]."""
    if length == 16:
        var res = _tls13_hkdf_expand_label[16](
            Span(secret), label, Span(context)
        )
        var out = List[UInt8](capacity=16)
        for i in range(16):
            out.append(res[i])
        return out^
    elif length == 12:
        var res = _tls13_hkdf_expand_label[12](
            Span(secret), label, Span(context)
        )
        var out = List[UInt8](capacity=12)
        for i in range(12):
            out.append(res[i])
        return out^
    elif length == 32:
        var res = _tls13_hkdf_expand_label[32](
            Span(secret), label, Span(context)
        )
        var out = List[UInt8](capacity=32)
        for i in range(32):
            out.append(res[i])
        return out^
    else:
        raise Error("Unsupported length for hkdf_expand_label")


fn _xor_iv(iv: InlineArray[UInt8, 12], seq: UInt64) -> InlineArray[UInt8, 12]:
    """XORs a sequence number into a TLS IV for GCM nonce construction."""
    var out = iv
    for i in range(8):
        out[11 - i] ^= UInt8((seq >> (i * 8)) & 0xFF)
    return out


fn _build_record_aad(length: Int) -> List[UInt8]:
    """Constructs the AAD for a TLS 1.3 encrypted record."""
    var aad = List[UInt8]()
    aad.append(0x17)
    aad.append(0x03)
    aad.append(0x03)
    var lb = _u16_to_bytes(UInt16(length))
    aad.append(lb[0])
    aad.append(lb[1])
    return aad^


fn _make_client_hello(
    host: String, client_random: List[UInt8], client_pub: List[UInt8]
) -> List[UInt8]:
    """Constructs a basic TLS 1.3 ClientHello message (Public API)."""
    var body = List[UInt8]()
    body.append(UInt8(0x03))
    body.append(UInt8(0x03))  # legacy_version
    for b in client_random:
        body.append(b)
    body.append(UInt8(0))  # session id length
    var cs = _u16_to_bytes(CIPHER_TLS_AES_128_GCM_SHA256)
    body.append(0)
    body.append(2)
    body.append(cs[0])
    body.append(cs[1])
    body.append(UInt8(1))
    body.append(UInt8(0))  # compression

    var ext = List[UInt8]()
    # SNI
    var host_bytes = _string_to_bytes(host)
    var sni_data = List[UInt8]()
    sni_data.append(0)
    var hlen = _u16_to_bytes(UInt16(len(host_bytes)))
    sni_data.append(hlen[0])
    sni_data.append(hlen[1])
    for b in host_bytes:
        sni_data.append(b)
    var sni_list_len = _u16_to_bytes(UInt16(len(sni_data)))
    var sni_ext_data = List[UInt8]()
    sni_ext_data.append(sni_list_len[0])
    sni_ext_data.append(sni_list_len[1])
    for b in sni_data:
        sni_ext_data.append(b)
    var sni_type = _u16_to_bytes(EXT_SNI)
    var sni_len_bytes = _u16_to_bytes(UInt16(len(sni_ext_data)))
    ext.append(sni_type[0])
    ext.append(sni_type[1])
    ext.append(sni_len_bytes[0])
    ext.append(sni_len_bytes[1])
    for b in sni_ext_data:
        ext.append(b)

    # supported_versions
    var ver_type = _u16_to_bytes(EXT_SUPPORTED_VERSIONS)
    ext.append(ver_type[0])
    ext.append(ver_type[1])
    ext.append(0)
    ext.append(3)
    ext.append(2)
    ext.append(0x03)
    ext.append(0x04)

    # supported_groups
    var groups_type = _u16_to_bytes(EXT_SUPPORTED_GROUPS)
    ext.append(groups_type[0])
    ext.append(groups_type[1])
    ext.append(0)
    ext.append(4)
    ext.append(0)
    ext.append(2)
    var g1d = _u16_to_bytes(GROUP_X25519)
    ext.append(g1d[0])
    ext.append(g1d[1])

    # signature_algorithms
    var sig_type = _u16_to_bytes(EXT_SIG_ALGS)
    var sigs = List[UInt8]()
    var s1 = _u16_to_bytes(SIG_ECDSA_SECP256R1_SHA256)
    var s2 = _u16_to_bytes(SIG_ECDSA_SECP384R1_SHA384)
    var s3 = _u16_to_bytes(SIG_RSA_PSS_RSAE_SHA256)
    var s4 = _u16_to_bytes(SIG_RSA_PKCS1_SHA256)
    var s5 = _u16_to_bytes(SIG_RSA_PKCS1_SHA384)
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
    var sig_list_len = _u16_to_bytes(UInt16(len(sigs)))
    ext.append(sig_type[0])
    ext.append(sig_type[1])
    var sig_ext_len = _u16_to_bytes(UInt16(len(sigs) + 2))
    ext.append(sig_ext_len[0])
    ext.append(sig_ext_len[1])
    ext.append(sig_list_len[0])
    ext.append(sig_list_len[1])
    for b in sigs:
        ext.append(b)

    # key_share
    var ks_type = _u16_to_bytes(EXT_KEY_SHARE)
    var ks_data = List[UInt8]()
    var kg = _u16_to_bytes(GROUP_X25519)
    ks_data.append(kg[0])
    ks_data.append(kg[1])
    var kpub_len = _u16_to_bytes(UInt16(len(client_pub)))
    ks_data.append(kpub_len[0])
    ks_data.append(kpub_len[1])
    for b in client_pub:
        ks_data.append(b)
    var ks_list_len = _u16_to_bytes(UInt16(len(ks_data)))
    ext.append(ks_type[0])
    ext.append(ks_type[1])
    var ks_ext_len = _u16_to_bytes(UInt16(len(ks_data) + 2))
    ext.append(ks_ext_len[0])
    ext.append(ks_ext_len[1])
    ext.append(ks_list_len[0])
    ext.append(ks_list_len[1])
    for b in ks_data:
        ext.append(b)

    var elen = _u16_to_bytes(UInt16(len(ext)))
    body.append(elen[0])
    body.append(elen[1])
    for b in ext:
        body.append(b)
    return body^


struct TLS13Client[T: TLSTransport](Movable):
    """TLS 1.3 Client implementation for secure communication."""

    var transport: T
    var host: String
    var keys: TLS13Keys
    var transcript: List[UInt8]
    var handshake_secret: List[UInt8]
    var shared_secret: InlineArray[UInt8, 32]
    var server_pubkey: List[UInt8]
    var app_seq_in: UInt64
    var app_seq_out: UInt64
    var hs_seq_in: UInt64
    var hs_seq_out: UInt64
    var handshake_done: Bool
    var defragmenter: HandshakeDefragmenter
    var post_handshake_defragmenter: HandshakeDefragmenter

    fn __init__(out self, var transport: T, host: String):
        """Initializes the client with a transport and remote host."""
        self.transport = transport^
        self.host = host
        self.keys = TLS13Keys()
        self.transcript = List[UInt8]()
        self.handshake_secret = List[UInt8]()
        self.shared_secret = InlineArray[UInt8, 32](0)
        self.server_pubkey = List[UInt8]()
        self.app_seq_in = 0
        self.app_seq_out = 0
        self.hs_seq_in = 0
        self.hs_seq_out = 0
        self.handshake_done = False
        self.defragmenter = HandshakeDefragmenter()
        self.post_handshake_defragmenter = HandshakeDefragmenter()

    fn __moveinit__(out self, deinit other: Self):
        """Move constructor for TLS13Client."""
        self.transport = other.transport^
        self.host = other.host
        self.keys = other.keys
        self.transcript = other.transcript^
        self.handshake_secret = other.handshake_secret^
        self.shared_secret = other.shared_secret
        self.server_pubkey = other.server_pubkey^
        self.app_seq_in = other.app_seq_in
        self.app_seq_out = other.app_seq_out
        self.hs_seq_in = other.hs_seq_in
        self.hs_seq_out = other.hs_seq_out
        self.handshake_done = other.handshake_done
        self.defragmenter = other.defragmenter^
        self.post_handshake_defragmenter = other.post_handshake_defragmenter^

    fn encrypt_record(
        self,
        payload: Span[UInt8],
        content_type: UInt8,
        key: Span[UInt8],
        iv: InlineArray[UInt8, 12],
        seq: UInt64,
    ) raises -> List[UInt8]:
        """Encrypts a TLS 1.3 record."""
        var inner = List[UInt8](capacity=len(payload) + 1)
        for i in range(len(payload)):
            inner.append(payload[i])
        inner.append(content_type)
        var aad = _build_record_aad(len(inner) + 16)
        var nonce = _xor_iv(iv, seq)
        var sealed = aes_gcm_seal_internal(
            key, Span(nonce), Span(aad), Span(inner)
        )
        var ciphertext = sealed.ciphertext.copy()
        var tag = sealed.tag

        var body = List[UInt8](capacity=len(ciphertext) + 16)
        for b in ciphertext:
            body.append(b)
        for i in range(16):
            body.append(tag[i])
        var record = List[UInt8](capacity=5 + len(body))
        record.append(0x17)
        record.append(0x03)
        record.append(0x03)
        var rlen = _u16_to_bytes(UInt16(len(body)))
        record.append(rlen[0])
        record.append(rlen[1])
        for b in body:
            record.append(b)
        return record^

    fn decrypt_record(
        self,
        payload: List[UInt8],
        key: Span[UInt8],
        iv: InlineArray[UInt8, 12],
        seq: UInt64,
    ) raises -> DecryptedRecord:
        """Decrypts a TLS 1.3 record."""
        if len(payload) < 16:
            raise Error("TLS decrypt: payload too short")
        var ct = List[UInt8]()
        for i in range(len(payload) - 16):
            ct.append(payload[i])
        var tag = InlineArray[UInt8, 16](0)
        for i in range(16):
            tag[i] = payload[len(payload) - 16 + i]
        var aad = _build_record_aad(len(payload))
        var nonce = _xor_iv(iv, seq)
        var opened = aes_gcm_open_internal(
            key, Span(nonce), Span(aad), Span(ct), tag
        )
        if not opened.success:
            raise Error("TLS decrypt: auth failed")
        var pt = opened.plaintext.copy()

        var idx = len(pt) - 1
        while idx >= 0 and pt[idx] == 0:
            idx -= 1
        if idx < 0:
            raise Error("TLS decrypt: no content type")
        var content_type = pt[idx]
        var content = List[UInt8]()
        for j in range(idx):
            content.append(pt[j])
        return DecryptedRecord(content^, content_type)

    fn read_record(mut self) raises -> TLSRecord:
        """Reads a single record from the transport."""
        var header = _read_exact(self.transport, 5)
        var length = Int(_bytes_to_u16(header, 3))
        var payload = _read_exact(self.transport, length)
        return TLSRecord(header[0], payload^)

    fn read_handshake_message(mut self) raises -> HandshakeMessage:
        """Reads a handshake message, skipping CCS and handling fragmentation.
        """
        while not self.defragmenter.has_full_message():
            var rec = self.read_record()
            if rec.content_type == 20:  # Skip ChangeCipherSpec
                continue
            if rec.content_type != 0x16:  # Handshake
                raise Error(
                    "Expected handshake record, got " + String(rec.content_type)
                )
            self.defragmenter.add_data(rec.payload)
        return self.defragmenter.next_message()

    fn read_handshake_message_encrypted(mut self) raises -> HandshakeMessage:
        """Reads an encrypted handshake message, skipping CCS and handling fragmentation.
        """
        while not self.defragmenter.has_full_message():
            var rec = self.read_record()
            if rec.content_type == 20:  # Skip ChangeCipherSpec
                continue
            if rec.content_type != 0x17:  # AppData (Encrypted)
                raise Error(
                    "Expected encrypted record, got " + String(rec.content_type)
                )

            var key = self.keys.server_hs_key.copy()
            var iv = self.keys.server_hs_iv
            var dec = self.decrypt_record(
                rec.payload,
                Span(key),
                iv,
                self.hs_seq_in,
            )
            self.hs_seq_in += 1

            if dec.inner_type == 0x16:  # Handshake
                self.defragmenter.add_data(dec.content)
            elif dec.inner_type == 21:  # Alert
                raise Error("TLS Alert received")
            else:
                # Skip other types (like NewSessionTicket if they appear as separate inner records)
                continue
        return self.defragmenter.next_message()

    fn send_handshake(mut self, msg: List[UInt8], encrypt: Bool) raises:
        """Encapsulates and sends a handshake message."""
        if encrypt:
            var key = self.keys.client_hs_key.copy()
            var iv = self.keys.client_hs_iv
            var record = self.encrypt_record(
                Span(msg),
                CONTENT_HANDSHAKE,
                Span(key),
                iv,
                self.hs_seq_out,
            )
            self.hs_seq_out += 1
            _ = self.transport.write(Span(_bytes_to_bytes(record)))
        else:
            var out = List[UInt8](capacity=5 + len(msg))
            out.append(0x16)
            out.append(0x03)
            out.append(0x03)
            var lb = _u16_to_bytes(UInt16(len(msg)))
            out.append(lb[0])
            out.append(lb[1])
            for b in msg:
                out.append(b)
            _ = self.transport.write(Span(_bytes_to_bytes(out)))

    fn _derive_keys(mut self, handshake_secret: Span[UInt8]) raises:
        """Derives handshake traffic keys."""
        var empty = List[UInt8]()
        var th_arr = sha256(self.transcript)

        var c_hs_secret = _tls13_hkdf_expand_label[32](
            handshake_secret, "c hs traffic", Span(th_arr)
        )
        self.keys.client_hs_secret = List[UInt8]()
        for i in range(32):
            self.keys.client_hs_secret.append(c_hs_secret[i])

        var s_hs_secret = _tls13_hkdf_expand_label[32](
            handshake_secret, "s hs traffic", Span(th_arr)
        )
        self.keys.server_hs_secret = List[UInt8]()
        for i in range(32):
            self.keys.server_hs_secret.append(s_hs_secret[i])

        var c_hs_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.client_hs_secret), "key", Span(empty)
        )
        self.keys.client_hs_key = List[UInt8]()
        for i in range(16):
            self.keys.client_hs_key.append(c_hs_key[i])

        var s_hs_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.server_hs_secret), "key", Span(empty)
        )
        self.keys.server_hs_key = List[UInt8]()
        for i in range(16):
            self.keys.server_hs_key.append(s_hs_key[i])

        self.keys.client_hs_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.client_hs_secret), "iv", Span(empty)
        )
        self.keys.server_hs_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.server_hs_secret), "iv", Span(empty)
        )

        var c_fin_key = _tls13_hkdf_expand_label[32](
            Span(self.keys.client_hs_secret), "finished", Span(empty)
        )
        self.keys.client_finished_key = List[UInt8]()
        for i in range(32):
            self.keys.client_finished_key.append(c_fin_key[i])

        var s_fin_key = _tls13_hkdf_expand_label[32](
            Span(self.keys.server_hs_secret), "finished", Span(empty)
        )
        self.keys.server_finished_key = List[UInt8]()
        for i in range(32):
            self.keys.server_finished_key.append(s_fin_key[i])

    fn _derive_app_keys(mut self, master_secret: Span[UInt8]) raises:
        """Derives application traffic keys."""
        var empty = List[UInt8]()
        var th_arr = sha256(self.transcript)

        var c_ap_secret = _tls13_hkdf_expand_label[32](
            master_secret, "c ap traffic", Span(th_arr)
        )
        self.keys.client_app_secret = List[UInt8]()
        for i in range(32):
            self.keys.client_app_secret.append(c_ap_secret[i])

        var s_ap_secret = _tls13_hkdf_expand_label[32](
            master_secret, "s ap traffic", Span(th_arr)
        )
        self.keys.server_app_secret = List[UInt8]()
        for i in range(32):
            self.keys.server_app_secret.append(s_ap_secret[i])

        var c_ap_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.client_app_secret), "key", Span(empty)
        )
        self.keys.client_app_key = List[UInt8]()
        for i in range(16):
            self.keys.client_app_key.append(c_ap_key[i])

        var s_ap_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.server_app_secret), "key", Span(empty)
        )
        self.keys.server_app_key = List[UInt8]()
        for i in range(16):
            self.keys.server_app_key.append(s_ap_key[i])

        self.keys.client_app_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.client_app_secret), "iv", Span(empty)
        )
        self.keys.server_app_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.server_app_secret), "iv", Span(empty)
        )

    fn _update_server_app_keys(mut self) raises:
        """Updates server application traffic keys after a KeyUpdate."""
        var empty = List[UInt8]()
        var next_secret = _tls13_hkdf_expand_label[32](
            Span(self.keys.server_app_secret), "traffic upd", Span(empty)
        )
        self.keys.server_app_secret = List[UInt8]()
        for i in range(32):
            self.keys.server_app_secret.append(next_secret[i])

        var next_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.server_app_secret), "key", Span(empty)
        )
        self.keys.server_app_key = List[UInt8]()
        for i in range(16):
            self.keys.server_app_key.append(next_key[i])

        self.keys.server_app_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.server_app_secret), "iv", Span(empty)
        )

    fn _update_client_app_keys(mut self) raises:
        """Updates client application traffic keys after sending a KeyUpdate."""
        var empty = List[UInt8]()
        var next_secret = _tls13_hkdf_expand_label[32](
            Span(self.keys.client_app_secret), "traffic upd", Span(empty)
        )
        self.keys.client_app_secret = List[UInt8]()
        for i in range(32):
            self.keys.client_app_secret.append(next_secret[i])

        var next_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.client_app_secret), "key", Span(empty)
        )
        self.keys.client_app_key = List[UInt8]()
        for i in range(16):
            self.keys.client_app_key.append(next_key[i])

        self.keys.client_app_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.client_app_secret), "iv", Span(empty)
        )

    fn _send_key_update(mut self, request_update: Bool) raises:
        """Sends a KeyUpdate and rotates client traffic keys."""
        var body = List[UInt8]()
        if request_update:
            body.append(1)
        else:
            body.append(0)
        var msg = _wrap_handshake(HS_KEY_UPDATE, body)

        var key = self.keys.client_app_key.copy()
        var iv = self.keys.client_app_iv
        var record = self.encrypt_record(
            Span(msg),
            CONTENT_HANDSHAKE,
            Span(key),
            iv,
            self.app_seq_out,
        )
        self.app_seq_out += 1
        _ = self.transport.write(Span(_bytes_to_bytes(record)))
        self._update_client_app_keys()

    fn perform_handshake(mut self) raises -> Bool:
        """Executes the TLS 1.3 handshake sequence."""
        var client_random = _random_bytes(32)
        var client_priv = _random_bytes(32)
        var base_u = List[UInt8]()
        base_u.append(9)
        for _ in range(31):
            base_u.append(0)
        var client_pub_arr = x25519(Span(client_priv), Span(base_u))
        var client_pub = List[UInt8]()
        for i in range(32):
            client_pub.append(client_pub_arr[i])

        var ch_body = _make_client_hello(self.host, client_random, client_pub)
        var ch_msg = _wrap_handshake(HS_CLIENT_HELLO, ch_body)
        self.transcript.extend(ch_msg.copy())
        self.send_handshake(ch_msg, False)

        # 1. Read ServerHello
        var sh_msg = self.read_handshake_message()
        self.transcript.extend(_wrap_handshake(sh_msg.msg_type, sh_msg.payload))

        var sh = ByteCursor(sh_msg.payload)
        _ = sh.read_u16()
        _ = sh.read_bytes(32)
        var session_id_len = Int(sh.read_u8())
        if session_id_len > 0:
            _ = sh.read_bytes(session_id_len)
        var cipher = sh.read_u16()
        _ = sh.read_u8()

        # Determine PRF based on cipher
        var use_sha384 = cipher == CIPHER_TLS_AES_256_GCM_SHA384

        var ext_len = Int(sh.read_u16())
        var ext_cur = ByteCursor(sh.read_bytes(ext_len))
        var server_pub = List[UInt8]()
        while ext_cur.remaining() > 0:
            var etype = ext_cur.read_u16()
            var elen = Int(ext_cur.read_u16())
            var edata = ext_cur.read_bytes(elen)
            if etype == EXT_KEY_SHARE:
                var ec = ByteCursor(edata)
                _ = ec.read_u16()
                var klen = Int(ec.read_u16())
                server_pub = ec.read_bytes(klen)

        var shared_arr = x25519(Span(client_priv), Span(server_pub))
        self.shared_secret = shared_arr

        # Key Schedule Phase 1: Handshake Secret
        var empty = List[UInt8]()
        if use_sha384:
            from crypto.hkdf import hkdf_extract_sha384
            from crypto.sha384 import sha384

            var zeros48 = List[UInt8]()
            for _ in range(48):
                zeros48.append(0)
            var early = hkdf_extract_sha384(Span(empty), Span(zeros48))
            var derived = _tls13_hkdf_expand_label_sha384[48](
                Span(early), "derived", Span(sha384(Span(empty)))
            )
            var hs_secret = hkdf_extract_sha384(Span(derived), Span(shared_arr))
            self.handshake_secret = List[UInt8]()
            for i in range(48):
                self.handshake_secret.append(hs_secret[i])
            # TODO: Add _derive_keys_sha384
        else:
            var zeros32 = zeros(32)
            var early = hkdf_extract(Span(empty), Span(zeros32))
            var derived = _tls13_hkdf_expand_label[32](
                Span(early), "derived", Span(sha256(Span(empty)))
            )
            var hs_secret = hkdf_extract(Span(derived), Span(shared_arr))
            self.handshake_secret = List[UInt8]()
            for i in range(32):
                self.handshake_secret.append(hs_secret[i])
            var hs_tmp = self.handshake_secret.copy()
            self._derive_keys(Span(hs_tmp))

        # 2. Process encrypted handshake flight
        var got_finished = False
        while not got_finished:
            var msg = self.read_handshake_message_encrypted()
            var full = _wrap_handshake(msg.msg_type, msg.payload)

            if msg.msg_type == HS_CERTIFICATE:
                var cert_cur = ByteCursor(msg.payload)
                var ctx_len = cert_cur.read_u8()
                _ = cert_cur.read_bytes(Int(ctx_len))
                var cert_list_len = cert_cur.read_u24()
                var clist_cur = ByteCursor(cert_cur.read_bytes(cert_list_len))
                var certs = List[List[UInt8]]()
                while clist_cur.remaining() > 0:
                    var c_len = clist_cur.read_u24()
                    certs.append(clist_cur.read_bytes(c_len))
                    var extensions_len = clist_cur.read_u16()
                    _ = clist_cur.read_bytes(Int(extensions_len))

                var trust = load_trust_store()
                if not verify_chain(certs, trust, _string_to_bytes(self.host)):
                    raise Error("Certificate verification failed")
                var parsed = parse_certificate(certs[0])
                self.server_pubkey = parsed.public_key.copy()

            elif msg.msg_type == HS_CERT_VERIFY:
                var cv_cur = ByteCursor(msg.payload)
                var sig_alg = cv_cur.read_u16()
                var sig_len = Int(cv_cur.read_u16())
                var sig = cv_cur.read_bytes(sig_len)

                var th_arr_cv = sha256(self.transcript)
                var padded = List[UInt8]()
                for _ in range(64):
                    padded.append(0x20)
                var context_str = "TLS 1.3, server CertificateVerify"
                for i in range(len(context_str)):
                    padded.append(ord(context_str[i]))
                padded.append(0)
                for i in range(32):
                    padded.append(th_arr_cv[i])

                if sig_alg == SIG_RSA_PSS_RSAE_SHA256:
                    if not verify_rsa_pss_sha256(
                        self.server_pubkey, padded, sig
                    ):
                        raise Error("RSA PSS signature failed")
                elif sig_alg == SIG_RSA_PKCS1_SHA256:
                    if not verify_rsa_pkcs1v15(self.server_pubkey, padded, sig):
                        raise Error("RSA PKCS1 signature failed")
                elif sig_alg == SIG_ECDSA_SECP256R1_SHA256:
                    var ph_arr = sha256(padded)
                    var ph = List[UInt8]()
                    for i in range(32):
                        ph.append(ph_arr[i])
                    if not verify_ecdsa_p256_hash(self.server_pubkey, ph, sig):
                        raise Error("ECDSA P256 signature failed")

            elif msg.msg_type == HS_FINISHED:
                var transcript_hash_fin = sha256(self.transcript)
                var expected_fin = hmac_sha256(
                    Span(self.keys.server_finished_key),
                    Span(transcript_hash_fin),
                )
                for i in range(32):
                    if msg.payload[i] != expected_fin[i]:
                        raise Error("Server Finished mismatch")

                self.transcript.extend(full^)
                var derived2 = _tls13_hkdf_expand_label[32](
                    Span(self.handshake_secret),
                    "derived",
                    Span(sha256(Span(List[UInt8]()))),
                )
                var master_arr = hkdf_extract(Span(derived2), Span(zeros(32)))
                var master = List[UInt8]()
                for i in range(32):
                    master.append(master_arr[i])
                self._derive_app_keys(Span(master))
                got_finished = True
                continue  # Skip the general transcript update at the end

            self.transcript.extend(full^)

        # 3. Send Client Finished
        var transcript_hash_f = sha256(self.transcript)
        var client_fin_verify = hmac_sha256(
            Span(self.keys.client_finished_key), Span(transcript_hash_f)
        )
        var fin_body = List[UInt8](capacity=32)
        for i in range(32):
            fin_body.append(client_fin_verify[i])
        var fin_msg = _wrap_handshake(HS_FINISHED, fin_body)
        self.send_handshake(fin_msg.copy(), True)
        self.transcript.extend(fin_msg^)

        self.handshake_done = True
        return True

    fn write_app_data(mut self, plaintext: List[UInt8]) raises:
        """Encrypts and sends application data."""
        var key = self.keys.client_app_key.copy()
        var iv = self.keys.client_app_iv
        var record = self.encrypt_record(
            Span(plaintext),
            CONTENT_APPDATA,
            Span(key),
            iv,
            self.app_seq_out,
        )
        self.app_seq_out += 1
        _ = self.transport.write(Span(_bytes_to_bytes(record)))

    fn read_app_data(mut self) raises -> List[UInt8]:
        """Reads and decrypts application data."""
        var out = List[UInt8]()
        while True:
            var r = self.read_record()

            # Skip unencrypted legacy records
            if (
                r.content_type == 20
                or r.content_type == 21
                or r.content_type == 22
            ):
                continue

            if r.content_type == CONTENT_APPDATA:  # 23
                var key = self.keys.server_app_key.copy()
                var iv = self.keys.server_app_iv
                var dec = self.decrypt_record(
                    r.payload,
                    Span(key),
                    iv,
                    self.app_seq_in,
                )
                self.app_seq_in += 1

                if dec.inner_type == CONTENT_APPDATA:
                    for i in range(len(dec.content)):
                        out.append(dec.content[i])
                    # After receiving application data, we continue reading ONLY if the
                    # transport has more data ready, otherwise we return what we have.
                    # This avoids stalling on keep-alive connections.
                    # For now, we return after each record to match the HTTP client loop.
                    return out^
                elif dec.inner_type == CONTENT_HANDSHAKE:
                    self.post_handshake_defragmenter.add_data(dec.content)
                    while self.post_handshake_defragmenter.has_full_message():
                        var hs_msg = (
                            self.post_handshake_defragmenter.next_message()
                        )
                        if hs_msg.msg_type == HS_KEY_UPDATE:
                            if len(hs_msg.payload) != 1:
                                raise Error("Invalid KeyUpdate payload length")
                            var request_update = hs_msg.payload[0] == 1
                            self._update_server_app_keys()
                            if request_update:
                                self._send_key_update(False)
                        else:
                            continue
                elif dec.inner_type == CONTENT_ALERT:
                    return out^
            elif r.content_type == CONTENT_ALERT:
                return out^
            else:
                continue


fn _bytes_to_bytes(list: List[UInt8]) -> List[Byte]:
    """Converts a UInt8 list to a Byte list."""

    var out = List[Byte](capacity=len(list))

    for i in range(len(list)):
        out.append(Byte(list[i]))

    return out^
