"""TLS record layer processing and key derivation helpers."""

from collections import List

from memory import Span

from crypto.aes_gcm import aes_gcm_seal_internal
from crypto.hkdf import hkdf_expand_label


struct HandshakeKeys:
    """Keys derived during the TLS handshake for a specific traffic direction.
    """

    var key: List[UInt8]
    var iv: List[UInt8]
    var finished_key: List[UInt8]

    fn __init__(
        out self,
        var key: List[UInt8],
        var iv: List[UInt8],
        var finished_key: List[UInt8],
    ):
        self.key = key^
        self.iv = iv^
        self.finished_key = finished_key^

    fn __moveinit__(out self, deinit other: Self):
        self.key = other.key^
        self.iv = other.iv^
        self.finished_key = other.finished_key^


fn derive_handshake_keys(
    secret: List[UInt8],
) raises -> HandshakeKeys:
    """Derives encryption key, IV and finished key from a handshake secret.

    Args:
        secret: The handshake secret.

    Returns:
        The derived keys.

    Raises:
        Error: If key derivation fails.
    """
    var key = hkdf_expand_label(secret, "key", List[UInt8](), 16)
    var iv = hkdf_expand_label(secret, "iv", List[UInt8](), 12)
    var finished = hkdf_expand_label(secret, "finished", List[UInt8](), 32)
    return HandshakeKeys(key^, iv^, finished^)


fn build_nonce(iv: List[UInt8], seq: UInt64) -> List[UInt8]:
    """Constructs a TLS 1.3 nonce by XORing the IV with the sequence number."""
    # Nonce = iv XOR (0^32 || seq^64) per TLS 1.3.
    var out = List[UInt8]()
    for i in range(len(iv)):
        out.append(iv[i])
    var seq_bytes = List[UInt8]()
    for i in range(8):
        var shift = (7 - i) * 8
        seq_bytes.append(UInt8((seq >> shift) & UInt64(0xFF)))
    for i in range(8):
        var idx = 4 + i
        out[idx] = UInt8(out[idx] ^ seq_bytes[i])
    return out^


struct SealedRecord(Movable):
    """Result of a record sealing operation."""

    var ciphertext: List[UInt8]
    var tag: List[UInt8]
    var nonce: List[UInt8]

    fn __init__(
        out self,
        var ciphertext: List[UInt8],
        var tag: List[UInt8],
        var nonce: List[UInt8],
    ):
        self.ciphertext = ciphertext^
        self.tag = tag^
        self.nonce = nonce^

    fn __moveinit__(out self, deinit other: Self):
        self.ciphertext = other.ciphertext^
        self.tag = other.tag^
        self.nonce = other.nonce^


struct RecordSealer:
    """Helper for sealing multiple TLS records with sequence number progression.
    """

    var key: List[UInt8]
    var iv: List[UInt8]
    var seq: UInt64

    fn __init__(out self, in_key: List[UInt8], in_iv: List[UInt8]):
        """Initializes the sealer with a key and IV base.

        Args:
            in_key: The 16-byte encryption key.
            in_iv: The 12-byte IV base.
        """
        self.key = in_key.copy()
        self.iv = in_iv.copy()
        self.seq = UInt64(0)

    fn seal(
        mut self, aad: List[UInt8], plaintext: List[UInt8]
    ) raises -> SealedRecord:
        """Seals a record and increments the internal sequence number.

        Args:
            aad: Additional authenticated data.
            plaintext: The data to encrypt and authenticate.

        Returns:
            A SealedRecord containing the ciphertext and authentication tag.

        Raises:
            Error: If encryption fails.
        """
        var nonce = build_nonce(self.iv, self.seq)
        var sealed = aes_gcm_seal_internal(
            Span(self.key), Span(nonce), Span(aad), Span(plaintext)
        )
        var ciphertext = sealed.ciphertext.copy()
        var tag_arr = sealed.tag

        var tag_list = List[UInt8](capacity=16)
        for i in range(16):
            tag_list.append(tag_arr[i])

        self.seq += UInt64(1)
        return SealedRecord(ciphertext^, tag_list^, nonce^)
