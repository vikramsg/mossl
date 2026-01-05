from pki.ecdsa_p384 import p384_p, p384_n, p384_gx, p384_gy
from crypto.bytes import bytes_to_hex
from pki.bigint import BigInt

fn main() raises:
    print("P:  " + bytes_to_hex(BigInt(p384_p()).to_be_bytes(48)))
    print("N:  " + bytes_to_hex(BigInt(p384_n()).to_be_bytes(48)))
    print("GX: " + bytes_to_hex(BigInt(p384_gx()).to_be_bytes(48)))
    print("GY: " + bytes_to_hex(BigInt(p384_gy()).to_be_bytes(48)))
