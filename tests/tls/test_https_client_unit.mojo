from testing import assert_equal, assert_true
import time

from lightbug_http.address import TCPAddr
from lightbug_http.connection import default_buffer_size
from lightbug_http.header import HeaderKey, Headers
from lightbug_http.http import HTTPResponse, HTTPRequest
from lightbug_http.io.bytes import Bytes, byte

from tls.https_client import HTTPReader, _read_until_eof, _read_response

struct MockHTTPReader(HTTPReader, Movable):
    var data: Bytes
    var read_pos: Int
    var stall: Bool

    fn __init__(out self, data: Bytes = Bytes(), stall: Bool = False):
        self.data = data.copy()
        self.read_pos = 0
        self.stall = stall

    fn read(mut self, mut buf: Bytes) raises -> UInt:
        if self.read_pos >= len(self.data):
            if self.stall:
                # Return 0 to simulate "no data yet" on keep-alive
                time.sleep(0.1)
                return 0
            raise Error("EOF")

        var to_read = min(buf.capacity, len(self.data) - self.read_pos)
        for i in range(to_read):
            buf[i] = self.data[self.read_pos + i]
        self.read_pos += to_read
        return UInt(to_read)


fn test_read_until_eof_timeout() raises:
    print("Testing _read_until_eof timeout...")
    var reader = MockHTTPReader(stall=True)

    var start = time.perf_counter()
    # 0.2s timeout, should hit it after ~2 reads (each sleeps 0.1s)
    var res = _read_until_eof(reader, timeout_seconds=0.2)
    var end = time.perf_counter()

    var duration = end - start
    print("Stalling read took: " + String(duration) + "s")

    assert_true(duration >= 0.2, "Should have waited at least the timeout")
    assert_true(duration < 1.0, "Should have timed out reasonably fast")
    assert_equal(len(res), 0, "Should have returned empty bytes on timeout")


fn test_read_response_content_length_zero() raises:
    print("Testing _read_response with Content-Length: 0 (should not stall)...")
    var raw = (
        String("HTTP/1.1 301 Moved Permanently\r\n")
        + String("Location: https://github.com/\r\n")
        + String("Content-Length: 0\r\n")
        + String("Connection: keep-alive\r\n")
        + String("\r\n")
    )

    var initial = Bytes()
    for i in range(len(raw)):
        initial.append(byte(String(raw[i])))

    var reader = MockHTTPReader(stall=True)

    var start = time.perf_counter()
    var res = _read_response(reader, initial^)
    var end = time.perf_counter()

    var duration = end - start
    print("Response parsing took: " + String(duration) + "s")

    assert_true(
        duration < 0.1, "Should have returned immediately without stalling"
    )
    assert_equal(res.status_code, 301)
    assert_equal(
        res.headers.get(HeaderKey.LOCATION).value(), "https://github.com/"
    )


fn main() raises:
    test_read_until_eof_timeout()
    test_read_response_content_length_zero()
