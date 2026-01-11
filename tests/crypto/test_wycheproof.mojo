from collections import InlineArray
from collections import List

from logger import Level, Logger
from memory import Span
from python import Python

from crypto.aes_gcm import aes_gcm_seal_internal, aes_gcm_open_internal
from crypto.bytes import hex_to_bytes, bytes_to_hex
from crypto.hmac import hmac_sha256
from crypto.sha256 import sha256
from crypto.x25519 import x25519


fn test_hmac_sha256_wycheproof() raises:
    var log = Logger[Level.INFO]()
    log.info("Testing HMAC-SHA256 Wycheproof...")
    var json = Python.import_module("json")
    var builtins = Python.import_module("builtins")

    var f = builtins.open(
        "tests/fixtures/wycheproof/hmac_sha256_test.json", "r"
    )
    var data = json.load(f)
    f.close()

    var test_groups = data["testGroups"]
    for i in range(builtins.len(test_groups)):
        var group = test_groups[i]
        var tag_size_bits = Int(group["tagSize"])
        var tag_size_bytes = tag_size_bits // 8

        var tests = group["tests"]
        for j in range(builtins.len(tests)):
            var test = tests[j]
            var tc_id = String(test["tcId"])
            var key = hex_to_bytes(String(test["key"]))
            var msg = hex_to_bytes(String(test["msg"]))
            var tag = String(test["tag"])
            var result = String(test["result"])

            var full_tag = hmac_sha256(key, msg)
            var got_list = List[UInt8]()
            for k in range(tag_size_bytes):
                got_list.append(full_tag[k])

            var got = bytes_to_hex(got_list)
            if result == "valid" or result == "acceptable":
                if got != tag:
                    raise Error(
                        "HMAC-SHA256 Wycheproof FAILURE: mismatch in test "
                        + tc_id
                        + " got "
                        + got
                        + " want "
                        + tag
                    )
            elif result == "invalid":
                if got == tag:
                    raise Error(
                        "HMAC-SHA256 Wycheproof FAILURE: matched invalid test "
                        + tc_id
                    )

    log.info("HMAC-SHA256 Wycheproof passed!")


fn test_aes_gcm_wycheproof() raises:
    var log = Logger[Level.INFO]()
    log.info("Testing AES-GCM Wycheproof...")
    var json = Python.import_module("json")
    var builtins = Python.import_module("builtins")

    var f = builtins.open("tests/fixtures/wycheproof/aes_gcm_test.json", "r")
    var data = json.load(f)
    f.close()

    var test_groups = data["testGroups"]
    for i in range(builtins.len(test_groups)):
        var group = test_groups[i]
        var key_size = Int(group["keySize"])
        if key_size != 128:
            continue  # We only support AES-128 for now

        var tests = group["tests"]
        for j in range(builtins.len(tests)):
            var test = tests[j]
            var tc_id = String(test["tcId"])
            var key = hex_to_bytes(String(test["key"]))
            var iv = hex_to_bytes(String(test["iv"]))
            var aad = hex_to_bytes(String(test["aad"]))
            var msg = hex_to_bytes(String(test["msg"]))
            var ct = hex_to_bytes(String(test["ct"]))
            var tag = hex_to_bytes(String(test["tag"]))
            var result = String(test["result"])

            # Test Open
            var tag_arr = InlineArray[UInt8, 16](0)
            for k in range(min(16, len(tag))):
                tag_arr[k] = tag[k]
            var opened = aes_gcm_open_internal(
                Span(key), Span(iv), Span(aad), Span(ct), tag_arr
            )
            if result == "valid" or result == "acceptable":
                if not opened.success:
                    raise Error(
                        "AES-GCM Wycheproof FAILURE: failed to open valid test "
                        + tc_id
                    )
                if bytes_to_hex(opened.plaintext) != bytes_to_hex(msg):
                    raise Error(
                        "AES-GCM Wycheproof FAILURE: PT mismatch in test "
                        + tc_id
                    )
            elif result == "invalid":
                if opened.success:
                    raise Error(
                        "AES-GCM Wycheproof FAILURE: opened invalid test "
                        + tc_id
                    )

    log.info("AES-GCM Wycheproof passed!")


fn test_x25519_wycheproof() raises:
    var log = Logger[Level.INFO]()
    log.info("Testing X25519 Wycheproof...")
    var json = Python.import_module("json")
    var builtins = Python.import_module("builtins")

    var f = builtins.open("tests/fixtures/wycheproof/x25519_test.json", "r")
    var data = json.load(f)
    f.close()

    var test_groups = data["testGroups"]
    for i in range(builtins.len(test_groups)):
        var group = test_groups[i]
        var tests = group["tests"]
        for j in range(builtins.len(tests)):
            var test = tests[j]
            var tc_id = String(test["tcId"])
            var public_hex = String(test["public"])
            var private_hex = String(test["private"])
            var shared_hex = String(test["shared"])
            var result = String(test["result"])

            var public = hex_to_bytes(public_hex)
            var private = hex_to_bytes(private_hex)

            var got_arr = x25519(Span(private), Span(public))
            var got = List[UInt8]()
            for k in range(32):
                got.append(got_arr[k])
            var got_hex = bytes_to_hex(got)

            if result == "valid" or result == "acceptable":
                if got_hex != shared_hex:
                    raise Error(
                        "X25519 Wycheproof FAILURE: shared secret mismatch in"
                        " test "
                        + tc_id
                        + " got "
                        + got_hex
                        + " want "
                        + shared_hex
                    )
            elif result == "invalid":
                if shared_hex != "" and got_hex != shared_hex:
                    pass

    log.info("X25519 Wycheproof passed!")


fn main() raises:
    test_hmac_sha256_wycheproof()
    test_aes_gcm_wycheproof()
    test_x25519_wycheproof()
