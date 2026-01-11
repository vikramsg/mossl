import time
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def bench_sha256(iterations):
    data = b'A' * 1024
    start = time.perf_counter()
    for _ in range(iterations):
        hashlib.sha256(data).digest()
    end = time.perf_counter()
    duration = end - start
    print(f"SHA-256 (1KB, {iterations} iterations): {duration:.4f}s ({iterations/duration:.2f} ops/sec)")

def bench_hmac(iterations):
    key = b'K' * 32
    data = b'A' * 1024
    start = time.perf_counter()
    for _ in range(iterations):
        hmac.new(key, data, hashlib.sha256).digest()
    end = time.perf_counter()
    duration = end - start
    print(f"HMAC-SHA256 (1KB, {iterations} iterations): {duration:.4f}s ({iterations/duration:.2f} ops/sec)")

def bench_aes_gcm(iterations):
    key = b'K' * 16
    iv = b'I' * 12
    aad = b''
    pt = b'A' * 1024
    aes = AESGCM(key)
    start = time.perf_counter()
    for _ in range(iterations):
        ct_tag = aes.encrypt(iv, pt, aad)
        aes.decrypt(iv, ct_tag, aad)
    end = time.perf_counter()
    duration = end - start
    print(f"AES-GCM Seal+Open (1KB, {iterations} iterations): {duration:.4f}s ({iterations/duration:.2f} ops/sec)")

if __name__ == "__main__":
    print("============================================================")
    print("Python Cryptography Micro-benchmark")
    print("============================================================")
    bench_sha256(10000)
    bench_hmac(10000)
    bench_aes_gcm(1000)
    print("============================================================")
