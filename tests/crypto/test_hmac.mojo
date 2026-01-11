from testing import assert_equal

from logger_utils import default_logger, log_info
from python import Python

from crypto.bytes import hex_to_bytes, bytes_to_hex
from crypto.hmac import hmac_sha256


fn test_hmac_sha256_vector() raises:
    var key = hex_to_bytes("6b6579")  # "key"
    var data = hex_to_bytes(
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67"
    )
    var got_arr = hmac_sha256(key, data)
    var got = List[UInt8]()
    for i in range(32):
        got.append(got_arr[i])
    assert_equal(
        bytes_to_hex(got),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
    )


fn test_hmac_sha256_wycheproof() raises:
    var log = default_logger()
    log_info(log, "Testing HMAC-SHA256 Wycheproof...")
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

    log_info(log, "HMAC-SHA256 Wycheproof passed!")


fn main() raises:
    test_hmac_sha256_vector()
    test_hmac_sha256_wycheproof()
