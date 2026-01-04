"""Toy HKDF implementation used to match Quint contract tests."""

fn hkdf_extract(salt: String, ikm: String) -> String:
    return "prk:" + salt + ":" + ikm

fn hkdf_expand(prk: String, info: String, length: Int) -> String:
    return "okm:" + prk + ":" + info + ":" + String(length)
