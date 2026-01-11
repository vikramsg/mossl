from collections import InlineArray, List
from time import perf_counter

from memory import Span

from crypto.aes_gcm import aes_gcm_seal_internal, aes_gcm_open_internal
from crypto.bytes import zeros
from crypto.hmac import hmac_sha256
from crypto.sha256 import sha256
from crypto.x25519 import x25519

fn bench_sha256(iterations: Int) raises:
    var data = List[UInt8]()
    for _ in range(1024):
        data.append(0x41)
    
    var start = perf_counter()
    for _ in range(iterations):
        _ = sha256(Span(data))
    var end = perf_counter()
    
    var duration = end - start
    print("SHA-256 (1KB, " + String(iterations) + " iterations): " + String(duration)[:6] + "s (" + String(iterations / duration)[:8] + " ops/sec)")

fn bench_hmac(iterations: Int) raises:
    var key = List[UInt8]()
    for _ in range(32):
        key.append(0x4B)
    var data = List[UInt8]()
    for _ in range(1024):
        data.append(0x41)
        
    var start = perf_counter()
    for _ in range(iterations):
        _ = hmac_sha256(Span(key), Span(data))
    var end = perf_counter()
    
    var duration = end - start
    print("HMAC-SHA256 (1KB, " + String(iterations) + " iterations): " + String(duration)[:6] + "s (" + String(iterations / duration)[:8] + " ops/sec)")

fn bench_aes_gcm(iterations: Int) raises:
    var key = List[UInt8]()
    for _ in range(16): key.append(0x4B)
    var iv = List[UInt8]()
    for _ in range(12): iv.append(0x49)
    var aad = List[UInt8]()
    var pt = List[UInt8]()
    for _ in range(1024): pt.append(0x41)
    
    var start = perf_counter()
    for _ in range(iterations):
        var sealed = aes_gcm_seal_internal(Span(key), Span(iv), Span(aad), Span(pt))
        _ = aes_gcm_open_internal(Span(key), Span(iv), Span(aad), Span(sealed.ciphertext), sealed.tag)
    var end = perf_counter()
    
    var duration = end - start
    print("AES-GCM Seal+Open (1KB, " + String(iterations) + " iterations): " + String(duration)[:6] + "s (" + String(iterations / duration)[:8] + " ops/sec)")

fn bench_x25519(iterations: Int) raises:
    var scalar = List[UInt8]()
    for _ in range(32): scalar.append(0x01)
    var u = List[UInt8]()
    for _ in range(32): u.append(0x09)
    
    var start = perf_counter()
    for _ in range(iterations):
        _ = x25519(Span(scalar), Span(u))
    var end = perf_counter()
    
    var duration = end - start
    print("X25519 (32B, " + String(iterations) + " iterations): " + String(duration)[:6] + "s (" + String(iterations / duration)[:8] + " ops/sec)")

fn main() raises:
    print("============================================================")
    print("Mojo Cryptography Micro-benchmark")
    print("============================================================")
    bench_sha256(10000)
    bench_hmac(10000)
    bench_aes_gcm(1000)
    bench_x25519(1000)
    print("============================================================")
