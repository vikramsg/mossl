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


struct TLS13Keys(Copyable):
    """Container for TLS 1.3 session keys and secrets."""

    var client_hs_secret: InlineArray[UInt8, 32]
    var server_hs_secret: InlineArray[UInt8, 32]
    var client_hs_key: InlineArray[UInt8, 16]
    var server_hs_key: InlineArray[UInt8, 16]
    var client_hs_iv: InlineArray[UInt8, 12]
    var server_hs_iv: InlineArray[UInt8, 12]
    var client_finished_key: InlineArray[UInt8, 32]
    var server_finished_key: InlineArray[UInt8, 32]

    var client_app_secret: InlineArray[UInt8, 32]
    var server_app_secret: InlineArray[UInt8, 32]
    var client_app_key: InlineArray[UInt8, 16]
    var server_app_key: InlineArray[UInt8, 16]
    var client_app_iv: InlineArray[UInt8, 12]
    var server_app_iv: InlineArray[UInt8, 12]

    fn __init__(out self):
        self.client_hs_secret = InlineArray[UInt8, 32](0)
        self.server_hs_secret = InlineArray[UInt8, 32](0)
        self.client_hs_key = InlineArray[UInt8, 16](0)
        self.server_hs_key = InlineArray[UInt8, 16](0)
        self.client_hs_iv = InlineArray[UInt8, 12](0)
        self.server_hs_iv = InlineArray[UInt8, 12](0)
        self.client_finished_key = InlineArray[UInt8, 32](0)
        self.server_finished_key = InlineArray[UInt8, 32](0)
        self.client_app_secret = InlineArray[UInt8, 32](0)
        self.server_app_secret = InlineArray[UInt8, 32](0)
        self.client_app_key = InlineArray[UInt8, 16](0)
        self.server_app_key = InlineArray[UInt8, 16](0)
        self.client_app_iv = InlineArray[UInt8, 12](0)
        self.server_app_iv = InlineArray[UInt8, 12](0)

    fn __copyinit__(out self, other: Self):
        self.client_hs_secret = other.client_hs_secret
        self.server_hs_secret = other.server_hs_secret
        self.client_hs_key = other.client_hs_key
        self.server_hs_key = other.server_hs_key
        self.client_hs_iv = other.client_hs_iv
        self.server_hs_iv = other.server_hs_iv
        self.client_finished_key = other.client_finished_key
        self.server_finished_key = other.server_finished_key
        self.client_app_secret = other.client_app_secret
        self.server_app_secret = other.server_app_secret
        self.client_app_key = other.client_app_key
        self.server_app_key = other.server_app_key
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


fn random_bytes(n: Int) raises -> List[UInt8]:
    """Generates n random bytes using OS source (Public API)."""
    return _random_bytes(n)


fn make_client_hello(
    host: String, client_random: List[UInt8], client_pub: List[UInt8]
) -> List[UInt8]:
    """Constructs a basic TLS 1.3 ClientHello message (Public API)."""
    return _make_client_hello(host, client_random, client_pub)


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


fn _random_bytes(n: Int) raises -> List[UInt8]:
    """Reads secure random bytes from /dev/urandom."""
    with open("/dev/urandom", "r") as f:
        return f.read_bytes(n)


fn _read_exact[
    T: TLSTransport
](mut transport: T, size: Int) raises -> List[UInt8]:
    """Reads exactly N bytes from the transport."""
    var out = List[UInt8]()
    while len(out) < size:
        var buf = Bytes(capacity=size - len(out))
        var n = transport.read(buf)
        if n == 0:
            raise Error("TLS read_exact: unexpected EOF")
        for i in range(n):
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
    """XORs a sequence number into a TLS IV for GCM nonce construction.

    Args:
        iv: The 12-byte IV base.
        seq: The 64-bit sequence number.

    Returns:
        The 12-byte XORed result.
    """
    var out = iv
    for i in range(8):
        out[11 - i] ^= UInt8((seq >> (i * 8)) & 0xFF)
    return out


fn _build_record_aad(length: Int) -> List[UInt8]:
    """Constructs the AAD for a TLS 1.3 encrypted record.

    Args:
        length: Total length of the encrypted record (including content type and tag).

    Returns:
        The 5-byte AAD header.
    """
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
    """Constructs a basic TLS 1.3 ClientHello message.

    Args:
        host: Target server hostname.
        client_random: 32-byte random value.
        client_pub: 32-byte public key.

    Returns:
        The full ClientHello handshake message.
    """
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
    var handshake_secret: InlineArray[UInt8, 32]
    var shared_secret: InlineArray[UInt8, 32]
    var server_pubkey: List[UInt8]
    var app_seq_in: UInt64
    var app_seq_out: UInt64
    var hs_seq_in: UInt64
    var hs_seq_out: UInt64
    var handshake_done: Bool

    fn __init__(out self, var transport: T, host: String):
        """Initializes the client with a transport and remote host."""
        self.transport = transport^
        self.host = host
        self.keys = TLS13Keys()
        self.transcript = List[UInt8]()
        self.handshake_secret = InlineArray[UInt8, 32](0)
        self.shared_secret = InlineArray[UInt8, 32](0)
        self.server_pubkey = List[UInt8]()
        self.app_seq_in = 0
        self.app_seq_out = 0
        self.hs_seq_in = 0
        self.hs_seq_out = 0
        self.handshake_done = False

    fn __moveinit__(out self, deinit other: Self):
        """Move constructor for TLS13Client."""
        self.transport = other.transport^
        self.host = other.host
        self.keys = TLS13Keys()
        self.keys.client_hs_secret = other.keys.client_hs_secret
        self.keys.server_hs_secret = other.keys.server_hs_secret
        self.keys.client_hs_key = other.keys.client_hs_key
        self.keys.server_hs_key = other.keys.server_hs_key
        self.keys.client_hs_iv = other.keys.client_hs_iv
        self.keys.server_hs_iv = other.keys.server_hs_iv
        self.keys.client_finished_key = other.keys.client_finished_key
        self.keys.server_finished_key = other.keys.server_finished_key
        self.keys.client_app_secret = other.keys.client_app_secret
        self.keys.server_app_secret = other.keys.server_app_secret
        self.keys.client_app_key = other.keys.client_app_key
        self.keys.server_app_key = other.keys.server_app_key
        self.keys.client_app_iv = other.keys.client_app_iv
        self.keys.server_app_iv = other.keys.server_app_iv
        self.transcript = other.transcript^
        self.handshake_secret = other.handshake_secret
        self.shared_secret = other.shared_secret
        self.server_pubkey = other.server_pubkey^
        self.app_seq_in = other.app_seq_in
        self.app_seq_out = other.app_seq_out
        self.hs_seq_in = other.hs_seq_in
        self.hs_seq_out = other.hs_seq_out
        self.handshake_done = other.handshake_done

    fn encrypt_record(
        self,
        payload: Span[UInt8],
        content_type: UInt8,
        key: InlineArray[UInt8, 16],
        iv: InlineArray[UInt8, 12],
        seq: UInt64,
    ) raises -> List[UInt8]:
        """Encrypts a TLS 1.3 record.

        Args:
            payload: The inner plaintext to encrypt.
            content_type: The TLS content type (e.g. handshake, app data).
            key: The 16-byte encryption key.
            iv: The 12-byte IV base.
            seq: The current sequence number.

        Returns:
            The full encrypted record including header and tag.

        Raises:
            Error: If encryption fails.
        """
        var inner = List[UInt8](capacity=len(payload) + 1)
        for i in range(len(payload)):
            inner.append(payload[i])
        inner.append(content_type)
        var aad = _build_record_aad(len(inner) + 16)
        var nonce = _xor_iv(iv, seq)
        var sealed = aes_gcm_seal_internal(
            Span(key), Span(nonce), Span(aad), Span(inner)
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
        key: InlineArray[UInt8, 16],
        iv: InlineArray[UInt8, 12],
        seq: UInt64,
    ) raises -> DecryptedRecord:
        """Decrypts a TLS 1.3 record and returns its inner content.

        Args:
            payload: The encrypted record payload.
            key: The 16-byte decryption key.
            iv: The 12-byte IV base.
            seq: The current sequence number.

        Returns:
            The decrypted content and its inner type.

        Raises:
            Error: If decryption or authentication fails.
        """
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
            Span(key), Span(nonce), Span(aad), Span(ct), tag
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
        """Reads a single record from the transport.

        Returns:
            The raw TLS record read.

        Raises:
            Error: If reading fails.
        """
        var header = _read_exact(self.transport, 5)
        var length = Int(_bytes_to_u16(header, 3))
        var payload = _read_exact(self.transport, length)
        return TLSRecord(header[0], payload^)

    fn send_handshake(mut self, msg: List[UInt8], encrypt: Bool) raises:
        """Encapsulates and sends a handshake message.

        Args:
            msg: The handshake message body.
            encrypt: True if the record should be encrypted.

        Raises:
            Error: If sending fails.
        """
        if encrypt:
            var record = self.encrypt_record(
                Span(msg),
                CONTENT_HANDSHAKE,
                self.keys.client_hs_key,
                self.keys.client_hs_iv,
                self.hs_seq_out,
            )
            self.hs_seq_out += 1
            from tls.tls13 import bytes_to_bytes

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
            from tls.tls13 import bytes_to_bytes

            _ = self.transport.write(Span(_bytes_to_bytes(out)))

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
        for b in ch_msg:
            self.transcript.append(b)
        self.send_handshake(ch_msg, False)

        var rec = self.read_record()
        if rec.content_type == CONTENT_ALERT:
            raise Error("TLS alert")
        var cursor = ByteCursor(rec.payload)
        var mt = cursor.read_u8()
        var ml = cursor.read_u24()
        var sh_body = cursor.read_bytes(ml)
        var sh_msg = _wrap_handshake(mt, sh_body)
        for b in sh_msg:
            self.transcript.append(b)

        var sh = ByteCursor(sh_body)
        _ = sh.read_u16()
        _ = sh.read_bytes(32)
        _ = sh.read_u8()
        var cipher = sh.read_u16()
        _ = sh.read_u8()
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
                _ = ec.read_u16()
                var klen = Int(ec.read_u16())
                server_pub = ec.read_bytes(klen)

        var shared_arr = x25519(Span(client_priv), Span(server_pub))

        var empty = List[UInt8]()
        var zeros32 = zeros(32)
        var empty_h_arr = sha256(empty)
        var th_arr = sha256(self.transcript)

        var early = hkdf_extract(Span(empty), Span(zeros32))
        var derived = _tls13_hkdf_expand_label[32](
            Span(early), "derived", Span(empty_h_arr)
        )
        var handshake_secret = hkdf_extract(Span(derived), Span(shared_arr))

        self.handshake_secret = handshake_secret
        self.shared_secret = shared_arr
        self.keys.client_hs_secret = _tls13_hkdf_expand_label[32](
            Span(handshake_secret), "c hs traffic", Span(th_arr)
        )
        self.keys.server_hs_secret = _tls13_hkdf_expand_label[32](
            Span(handshake_secret), "s hs traffic", Span(th_arr)
        )
        self.keys.client_hs_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.client_hs_secret), "key", Span(empty)
        )
        self.keys.server_hs_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.server_hs_secret), "key", Span(empty)
        )
        self.keys.client_hs_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.client_hs_secret), "iv", Span(empty)
        )
        self.keys.server_hs_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.server_hs_secret), "iv", Span(empty)
        )
        self.keys.client_finished_key = _tls13_hkdf_expand_label[32](
            Span(self.keys.client_hs_secret), "finished", Span(empty)
        )
        self.keys.server_finished_key = _tls13_hkdf_expand_label[32](
            Span(self.keys.server_hs_secret), "finished", Span(empty)
        )

        var handshake_buf = List[UInt8]()
        var got_finished = False
        while not got_finished:
            var r2 = self.read_record()
            if r2.content_type != CONTENT_APPDATA:
                continue
            var dec = self.decrypt_record(
                r2.payload,
                self.keys.server_hs_key,
                self.keys.server_hs_iv,
                self.hs_seq_in,
            )
            self.hs_seq_in += 1
            if dec.inner_type == CONTENT_HANDSHAKE:
                for b in dec.content:
                    handshake_buf.append(b)
                while len(handshake_buf) >= 4:
                    var hc = ByteCursor(handshake_buf)
                    var hmt = hc.read_u8()
                    var hml = hc.read_u24()
                    if hc.remaining() < hml:
                        break
                    var hbody = hc.read_bytes(hml)
                    var full = _wrap_handshake(hmt, hbody)
                    if hmt == HS_FINISHED:
                        got_finished = True
                    if hmt == HS_CERTIFICATE:
                        var cert_cur = ByteCursor(hbody)
                        _ = cert_cur.read_u8()
                        var clen = cert_cur.read_u24()
                        var clist_cur = ByteCursor(cert_cur.read_bytes(clen))
                        var cert_der = clist_cur.read_bytes(
                            clist_cur.read_u24()
                        )
                        var parsed = parse_certificate(cert_der)
                        self.server_pubkey = parsed.public_key.copy()
                    for b in full:
                        self.transcript.append(b)
                    var nb = List[UInt8]()
                    for i in range(hc.pos, len(handshake_buf)):
                        nb.append(handshake_buf[i])
                    handshake_buf = nb^
                    if got_finished:
                        break

        th_arr = sha256(self.transcript)
        var derived2 = _tls13_hkdf_expand_label[32](
            Span(handshake_secret), "derived", Span(empty_h_arr)
        )
        var master = hkdf_extract(Span(derived2), Span(zeros32))
        self.keys.client_app_secret = _tls13_hkdf_expand_label[32](
            Span(master), "c ap traffic", Span(th_arr)
        )
        self.keys.server_app_secret = _tls13_hkdf_expand_label[32](
            Span(master), "s ap traffic", Span(th_arr)
        )

        var finished_arr = hmac_sha256(
            self.keys.client_finished_key, Span(th_arr)
        )
        var fin_body = List[UInt8](capacity=32)
        for i in range(32):
            fin_body.append(finished_arr[i])
        var fin_msg = _wrap_handshake(HS_FINISHED, fin_body)
        self.send_handshake(fin_msg, True)
        for b in fin_msg:
            self.transcript.append(b)

        self.keys.client_app_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.client_app_secret), "key", Span(empty)
        )
        self.keys.server_app_key = _tls13_hkdf_expand_label[16](
            Span(self.keys.server_app_secret), "key", Span(empty)
        )
        self.keys.client_app_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.client_app_secret), "iv", Span(empty)
        )
        self.keys.server_app_iv = _tls13_hkdf_expand_label[12](
            Span(self.keys.server_app_secret), "iv", Span(empty)
        )
        self.handshake_done = True
        return True

    fn write_app_data(mut self, plaintext: List[UInt8]) raises:
        """Encrypts and sends application data.

        Args:
            plaintext: The application data to send.

        Raises:
            Error: If encryption or sending fails.
        """
        var record = self.encrypt_record(
            Span(plaintext),
            CONTENT_APPDATA,
            self.keys.client_app_key,
            self.keys.client_app_iv,
            self.app_seq_out,
        )
        self.app_seq_out += 1
        from tls.tls13 import bytes_to_bytes

        _ = self.transport.write(Span(_bytes_to_bytes(record)))

    fn read_app_data(mut self) raises -> List[UInt8]:
        """Reads and decrypts application data from the transport.

        Returns:
            The decrypted application data content.

        Raises:
            Error: If reading or decryption fails.
        """
        while True:
            var r = self.read_record()
            if r.content_type != CONTENT_APPDATA:
                continue
            var dec = self.decrypt_record(
                r.payload,
                self.keys.server_app_key,
                self.keys.server_app_iv,
                self.app_seq_in,
            )
            self.app_seq_in += 1
            var inner_type = dec.inner_type
            if inner_type == CONTENT_APPDATA:
                return dec.content.copy()


fn _bytes_to_bytes(list: List[UInt8]) -> Bytes:
    """Converts a UInt8 list to a Lightbug Bytes object.

    Args:
        list: The source list of bytes.

    Returns:
        A Bytes object containing the same data.
    """
    var out = Bytes(capacity=len(list))
    for b in list:
        out.append(Byte(b))
    return out^
