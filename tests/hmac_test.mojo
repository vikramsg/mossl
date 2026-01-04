from test_utils import require

from crypto.hmac import hmac_sha256
from crypto.bytes import hex_to_bytes, bytes_to_hex

fn main() raises:
    var key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    var data = hex_to_bytes("4869205468657265")
    var mac = hmac_sha256(key, data)
    var mac_hex = bytes_to_hex(mac)
    require(mac_hex == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "HMAC-SHA256 vector")
