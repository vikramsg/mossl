from collections import List
from testing import assert_equal

from pki.x509 import parse_certificate, verify_signature_with_issuer, to_string


fn read_file_bytes(path: String) raises -> List[UInt8]:
    var f = open(path, "r")
    var b = f.read_bytes()
    f.close()
    var out = List[UInt8]()
    for i in range(len(b)):
        out.append(UInt8(b[i]))
    return out^


fn fixture_path(name: String) -> String:
    return "tests/fixtures/" + name


fn test_wikipedia_parsing() raises:
    print("Testing Wikipedia certificate parsing...")
    var leaf_bytes = read_file_bytes(fixture_path("wiki_leaf.der"))
    var leaf = parse_certificate(leaf_bytes)
    assert_equal(to_string(leaf.subject_cn), "*.wikipedia.org")
    assert_equal(to_string(leaf.issuer_cn), "E8")
    print("  SUCCESS")


fn test_wikipedia_signature() raises:
    print("Testing Wikipedia signature verification...")
    var leaf_bytes = read_file_bytes(fixture_path("wiki_leaf.der"))
    var inter_bytes = read_file_bytes(fixture_path("wiki_inter.der"))

    var leaf = parse_certificate(leaf_bytes)
    var inter = parse_certificate(inter_bytes)

    var ok = verify_signature_with_issuer(leaf, inter.public_key)
    assert_equal(ok, True)
    print("  SUCCESS")


fn test_microsoft_signature() raises:
    print("Testing Microsoft RSA signature verification...")
    var leaf_bytes = read_file_bytes(fixture_path("microsoft_leaf.der"))
    var inter_bytes = read_file_bytes(fixture_path("microsoft_inter.der"))

    var leaf = parse_certificate(leaf_bytes)
    var inter = parse_certificate(inter_bytes)

    var ok = verify_signature_with_issuer(leaf, inter.public_key)
    assert_equal(ok, True)
    print("  SUCCESS")


fn main() raises:
    test_wikipedia_parsing()
    test_wikipedia_signature()
    test_microsoft_signature()
