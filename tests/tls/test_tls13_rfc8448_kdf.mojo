from collections import List
from testing import assert_equal

# TODO(0.25.7): Replace manual main/test execution with stdlib TestSuite once available.
from crypto.hkdf import hkdf_extract
from crypto.sha256 import sha256
from crypto.bytes import hex_to_bytes, bytes_to_hex, zeros
from tls.tls13 import hkdf_expand_label
from memory import Span


fn test_rfc8448_kdf() raises:
    # RFC 8448 Section 3 key schedule values.
    var empty = List[UInt8]()
    var empty_hash_arr = sha256(empty)
    var empty_hash = List[UInt8]()
    for i in range(32):
        empty_hash.append(empty_hash_arr[i])
    var zeros32 = zeros(32)
    var early_arr = hkdf_extract(Span(empty), Span(zeros32))
    var early = List[UInt8]()
    for i in range(32):
        early.append(early_arr[i])
    assert_equal(
        bytes_to_hex(early),
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
    )
    var derived = hkdf_expand_label(early, "derived", empty_hash, 32)
    assert_equal(
        bytes_to_hex(derived),
        "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
    )

    var shared = hex_to_bytes(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
    )
    var handshake_arr = hkdf_extract(Span(derived), Span(shared))
    var handshake = List[UInt8]()
    for i in range(32):
        handshake.append(handshake_arr[i])
    assert_equal(
        bytes_to_hex(handshake),
        "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
    )

    var th = hex_to_bytes(
        "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
    )
    var client_hs = hkdf_expand_label(handshake, "c hs traffic", th, 32)
    assert_equal(
        bytes_to_hex(client_hs),
        "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
    )
    var server_hs = hkdf_expand_label(handshake, "s hs traffic", th, 32)
    assert_equal(
        bytes_to_hex(server_hs),
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
    )

    var derived2 = hkdf_expand_label(handshake, "derived", empty_hash, 32)
    var master_arr = hkdf_extract(Span(derived2), Span(zeros32))
    var master = List[UInt8]()
    for i in range(32):
        master.append(master_arr[i])
    assert_equal(
        bytes_to_hex(master),
        "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
    )

    var app_th = hex_to_bytes(
        "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
    )
    var client_app = hkdf_expand_label(master, "c ap traffic", app_th, 32)
    assert_equal(
        bytes_to_hex(client_app),
        "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
    )
    var server_app = hkdf_expand_label(master, "s ap traffic", app_th, 32)
    assert_equal(
        bytes_to_hex(server_app),
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
    )


fn main() raises:
    test_rfc8448_kdf()
