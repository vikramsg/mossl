from src.crypto.hkdf import hkdf_extract, hkdf_expand

fn main() raises:
    let prk1 = hkdf_extract("salt", "ikm")
    let prk2 = hkdf_extract("salt", "ikm")
    assert(prk1 == prk2, "extract must be deterministic")

    let okm1 = hkdf_expand("prk", "info", 32)
    let okm2 = hkdf_expand("prk", "info", 32)
    assert(okm1 == okm2, "expand must be deterministic")

    let okm_short = hkdf_expand("prk", "info", 16)
    assert(okm1 != okm_short, "length must affect output")
