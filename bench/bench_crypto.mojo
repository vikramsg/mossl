from time import perf_counter
from collections import List
from python import Python

from pki.rsa import verify_rsa_pkcs1v15
from pki.ecdsa_p384 import verify_ecdsa_p384_hash
from crypto.sha384 import sha384_bytes
from pki.bigint import BigInt, mod_pow
from crypto.bytes import hex_to_bytes

# --- Constants ---

fn get_msg() -> List[UInt8]:
    return hex_to_bytes("48656c6c6f204d6f6a6f2042656e63686d61726b")

fn get_rsa_pub() -> List[UInt8]:
    return hex_to_bytes("30820122300d06092a864886f70d01010105000382010f003082010a0282010100e207016f182663eb143905a473fcd2b4ad71f46bc8460e81a42c58a0727de3d9332b4708f828fa232f47b3abfc6b019971e4f3c02ee19910a79c0281a80151820ed3d46003bf4a81b4f87f10fc6305a711730940bb5925d3eaa55e30a40297a5f2e51c2eb23cc793d21dd7f2df877bb04c6b724e008300ac88dd1ed1d7971c9ec4927febe8d8037ef46e49b59a411c61c7192bfc62db6a638905faf4c67fbd86cc8d3fc241e71496cb63b6f3e7bfb98d0df252152c6aeefdac023eab340e76a2ca4f2d4219720c4b1cb39c14cbd69a2048e3320c8232e8c63d5b7dee07a4747dead4fb2d2aee1ff5b908bd9005ac33fc431fce97ccd0e7862d47f7449947698f0203010001")

fn get_rsa_sig() -> List[UInt8]:
    return hex_to_bytes("95a9fc52806c68693b153b345c6b7f5083a5dbccfd3b2669796f8c63c6537e916ebe1fc1a285ccb4867ed13023bdb0ef7ae471a33c7c78fdfeee5d44e6fcf171e8e1f8dcb0e6c8c7bc6aa36ae3e1ac1d7f1341b7e813898175f824a8e4472681b2ab77413c93119d21be0d0a95ad1e2209cbd6358416c6ce7787e8fac2cedb52b9fb975e509fe206218d1359d3314f38be80fab8af7830e5174409db134b1e9762d33bac354b8a86376d9a7b6e125f45351789a6de46e1f062ae2406bef5e939f31db804deadd0afb4104ac6ea5bfa153f5629ef642118fe4259464a8b2ce26e9844f4d2434463a417d726d9e17eef55312c4b4d0e19f6177ee7070251870cf4")

fn get_p384_pub() -> List[UInt8]:
    return hex_to_bytes("04280d5497dec9fbda14637931d3a5ba60edca91ff2e9e5e9f5278acf10d371d5b2bd9e4ddc860c4c068cca7d5ca8db789129ca87576f9e0f9d172aa6061ab56ba36719c7a402c84d425da94646c105f1178326e9c323e79c87a7149bd990c4f6d")

fn get_p384_sig() -> List[UInt8]:
    return hex_to_bytes("3065023100d5132ebda8a826ce08208f819d7afd25aba53d94e316f86253ed0f547be7070368d089211e6e75c94ae9acb69847183d0230562e2b43b16cf7cf312b2e74d6b751c4144ca91579d1452cc9ea5ebdcd84f945445d9b338b232671fcd5003e74258058")

fn get_rsa_n_hex() -> String:
    return "e207016f182663eb143905a473fcd2b4ad71f46bc8460e81a42c58a0727de3d9332b4708f828fa232f47b3abfc6b019971e4f3c02ee19910a79c0281a80151820ed3d46003bf4a81b4f87f10fc6305a711730940bb5925d3eaa55e30a40297a5f2e51c2eb23cc793d21dd7f2df877bb04c6b724e008300ac88dd1ed1d7971c9ec4927febe8d8037ef46e49b59a411c61c7192bfc62db6a638905faf4c67fbd86cc8d3fc241e71496cb63b6f3e7bfb98d0df252152c6aeefdac023eab340e76a2ca4f2d4219720c4b1cb39c14cbd69a2048e3320c8232e8c63d5b7dee07a4747dead4fb2d2aee1ff5b908bd9005ac33fc431fce97ccd0e7862d47f7449947698f"

fn get_rsa_e_hex() -> String:
    return "10001"

fn get_rsa_sig_hex() -> String:
    return "95a9fc52806c68693b153b345c6b7f5083a5dbccfd3b2669796f8c63c6537e916ebe1fc1a285ccb4867ed13023bdb0ef7ae471a33c7c78fdfeee5d44e6fcf171e8e1f8dcb0e6c8c7bc6aa36ae3e1ac1d7f1341b7e813898175f824a8e4472681b2ab77413c93119d21be0d0a95ad1e2209cbd6358416c6ce7787e8fac2cedb52b9fb975e509fe206218d1359d3314f38be80fab8af7830e5174409db134b1e9762d33bac354b8a86376d9a7b6e125f45351789a6de46e1f062ae2406bef5e939f31db804deadd0afb4104ac6ea5bfa153f5629ef642118fe4259464a8b2ce26e9844f4d2434463a417d726d9e17eef55312c4b4d0e19f6177ee7070251870cf4"

# --- Benchmarks ---

fn benchmark_rsa() raises:
    var pub = get_rsa_pub()
    var msg = get_msg()
    var sig = get_rsa_sig()
    
    # Warmup
    var ok = False
    try:
        ok = verify_rsa_pkcs1v15(pub, msg, sig)
    except:
        print("RSA Warmup raised exception")
    
    if not ok:
        print("RSA Verify failed during warmup")

    var start = perf_counter()
    var iters = 100
    for _ in range(iters):
        try:
            _ = verify_rsa_pkcs1v15(pub, msg, sig)
        except:
            print("RSA Verify failed")
    var end = perf_counter()
    
    var dur = end - start
    print("RSA-2048 Verify (Mojo):", iters / dur, "ops/sec")

fn benchmark_ecdsa_p384() raises:
    var pub = get_p384_pub()
    var msg = get_msg()
    var sig = get_p384_sig()
    var digest = sha384_bytes(msg)

    # Warmup
    var ok = False
    try:
        ok = verify_ecdsa_p384_hash(pub, digest, sig)
    except:
        print("ECDSA Warmup raised exception")

    if not ok:
        print("ECDSA Verify failed during warmup")

    var start = perf_counter()
    var iters = 10
    for _ in range(iters):
        try:
            _ = verify_ecdsa_p384_hash(pub, digest, sig)
        except:
            print("ECDSA Verify failed")
    var end = perf_counter()
    
    var dur = end - start
    print("ECDSA P-384 Verify (Mojo):", iters / dur, "ops/sec")

fn benchmark_bigint_pow():
    var n = BigInt.from_be_bytes(hex_to_bytes(get_rsa_n_hex()))
    var e = BigInt.from_be_bytes(hex_to_bytes(get_rsa_e_hex()))
    var s = BigInt.from_be_bytes(hex_to_bytes(get_rsa_sig_hex())) # Treating sig as a large number
    
    # Warmup
    _ = mod_pow(s.limbs, e.limbs, n.limbs)

    var start = perf_counter()
    var iters = 100
    for _ in range(iters):
        _ = mod_pow(s.limbs, e.limbs, n.limbs)
    var end = perf_counter()
    
    var dur = end - start
    print("BigInt ModPow (2048-bit) (Mojo):", iters / dur, "ops/sec")

fn main() raises:
    print("Running Mojo Benchmarks...")
    benchmark_rsa()
    benchmark_ecdsa_p384()
    benchmark_bigint_pow()