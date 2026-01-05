from collections import List
from time import perf_counter
from pki.x509 import parse_certificate, verify_chain
from pki.trust_store import load_trust_store
from crypto.bytes import hex_to_bytes

fn main() raises:
    # Load wiki leaf and inter from fixtures
    var f1 = open("tests/fixtures/wiki_leaf.der", "r")
    var leaf_der = f1.read_bytes()
    f1.close()
    
    var f2 = open("tests/fixtures/wiki_inter.der", "r")
    var inter_der = f2.read_bytes()
    f2.close()
    
    var certs = List[List[UInt8]]()
    var leaf_list = List[UInt8]()
    for i in range(len(leaf_der)): leaf_list.append(UInt8(leaf_der[i]))
    certs.append(leaf_list)
    
    var inter_list = List[UInt8]()
    for i in range(len(inter_der)): inter_list.append(UInt8(inter_der[i]))
    certs.append(inter_list)
    
    print("Loading trust store...")
    var start = perf_counter()
    var trust = load_trust_store()
    print("Trust store loaded in", perf_counter() - start, "s")
    
    var hostname = List[UInt8]()
    for b in "www.wikipedia.org".as_bytes(): hostname.append(UInt8(b))
    
    print("Benchmarking verify_chain...")
    start = perf_counter()
    var ok = verify_chain(certs, trust, hostname)
    var dur = perf_counter() - start
    print("verify_chain took", dur, "s (result:", ok, ")")
