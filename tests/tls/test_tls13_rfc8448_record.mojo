from collections import List
from testing import assert_equal

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from crypto.aes_gcm import aes_gcm_open
from crypto.bytes import hex_to_bytes, bytes_to_hex
from tls.record_layer import build_nonce


fn build_record_aad(length: Int) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8(0x17))
    out.append(UInt8(0x03))
    out.append(UInt8(0x03))
    out.append(UInt8((length >> 8) & 0xFF))
    out.append(UInt8(length & 0xFF))
    return out^


struct DecryptedInner(Movable):
    var content: List[UInt8]
    var content_type: UInt8

    fn __init__(out self, var content: List[UInt8], content_type: UInt8):
        self.content = content^
        self.content_type = content_type

    fn __moveinit__(out self, deinit other: Self):
        self.content = other.content^
        self.content_type = other.content_type


fn strip_inner_plaintext(inner: List[UInt8]) -> DecryptedInner:
    var idx = len(inner) - 1
    while idx >= 0 and inner[idx] == UInt8(0):
        idx -= 1
    if idx < 0:
        return DecryptedInner(List[UInt8](), UInt8(0))
    var content_type = inner[idx]
    var content = List[UInt8]()
    for i in range(idx):
        content.append(inner[i])
    return DecryptedInner(content^, content_type)


fn test_rfc8448_server_handshake_record() raises:
    # RFC 8448 Section 3 (Simple 1-RTT) server handshake record.
    var record = hex_to_bytes(
        "1703030061"
        "dc48237b4b879f50d0d4d262ea8b4716eb40ddc1eb957e11126e8a71"
        "49c2d012d37a7115957e64ce30008b9e0323f2c05a9c1c77b4f37849a6"
        "95ab255060a33fee770ca95cb8486bfd0843b87024865ca35cc41c4e51"
        "5c64dcb1369f98635bc7a5"
    )
    var payload = List[UInt8]()
    var i = 5
    while i < len(record):
        payload.append(record[i])
        i += 1

    var key = hex_to_bytes("27c6bdc0a3dcea39a47326d79bc9e4ee")
    var iv = hex_to_bytes("9569ecdd4d0536705e9ef725")
    var aad = build_record_aad(len(payload))
    var nonce = build_nonce(iv, UInt64(0))

    var ct = List[UInt8]()
    var tag = List[UInt8]()
    for j in range(len(payload) - 16):
        ct.append(payload[j])
    for j in range(len(payload) - 16, len(payload)):
        tag.append(payload[j])

    var opened = aes_gcm_open(key, nonce, aad, ct, tag)
    assert_equal(opened.success, True)
    var inner = opened.plaintext.copy()
    var stripped = strip_inner_plaintext(inner)
    assert_equal(stripped.content_type, UInt8(0x16))

    var expected = hex_to_bytes(
        "080000280026000a00140012001d00170018001901000101010201030104"
        "001c0002400100000000002a0000"
        "1400002048d3e0e1b3d907c6acff145e16090388c77b05c050b634ab1a88"
        "bbd0dd1a34b2"
    )
    assert_equal(bytes_to_hex(stripped.content), bytes_to_hex(expected))


fn main() raises:
    test_rfc8448_server_handshake_record()
