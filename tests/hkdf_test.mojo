from test_utils import require

from crypto.hkdf import hkdf_extract, hkdf_expand
from crypto.bytes import hex_to_bytes, bytes_to_hex

fn main() raises:
    var ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    var salt = hex_to_bytes("000102030405060708090a0b0c")
    var info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9")

    var prk = hkdf_extract(salt, ikm)
    var prk_hex = bytes_to_hex(prk)
    require(prk_hex == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "HKDF extract vector")

    var okm = hkdf_expand(prk, info, 42)
    var okm_hex = bytes_to_hex(okm)
    require(okm_hex == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "HKDF expand vector")
