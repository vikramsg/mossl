"""Local HTTPS client shim that uses TLSSocket without modifying lightbug_http."""
import time

from lightbug_http.address import TCPAddr
from lightbug_http.connection import default_buffer_size
from lightbug_http.cookie.response_cookie_jar import ResponseCookieJar
from lightbug_http.header import HeaderKey, Headers
from lightbug_http.http import HTTPRequest, HTTPResponse, encode
from lightbug_http.io.bytes import ByteReader, Bytes, byte
from lightbug_http.uri import URI, Scheme
from memory import Span

from tls.connect_https import connect_https
from tls.tls_socket import TLSSocket, SocketTransport
from tls.transport import TLSTransport

trait HTTPReader(Movable):
    fn read(mut self, mut buf: Bytes) raises -> UInt:
        ...


struct TLSConnectionAdapter[T: TLSTransport](HTTPReader, Movable):
    var tls: TLSSocket[T]

    var closed: Bool

    fn __init__(out self, var tls: TLSSocket[T]):
        self.tls = tls^

        self.closed = False

    fn read(mut self, mut buf: Bytes) raises -> UInt:
        return UInt(self.tls.read(buf))

    fn write(mut self, buf: Span[Byte]) raises -> UInt:
        return UInt(self.tls.write(buf))

    fn close(mut self) raises:
        self.tls.close()

    fn shutdown(mut self) raises -> None:
        self.tls.shutdown()

    fn teardown(mut self) raises:
        self.tls.teardown()

    fn local_addr(self) -> TCPAddr:
        return self.tls.local_addr()

    fn remote_addr(self) -> TCPAddr:
        return self.tls.remote_addr()

    fn is_closed(self) -> Bool:
        return self.closed


fn _read_until_eof[
    R: HTTPReader
](mut conn: R, timeout_seconds: Float64 = 5.0) raises -> Bytes:
    var out = Bytes()

    var buff = Bytes(capacity=default_buffer_size)

    var start = time.perf_counter()

    while True:
        if time.perf_counter() - start > timeout_seconds:
            return out^

        var n: UInt

        try:
            n = conn.read(buff)

        except e:
            if String(e) == "EOF":
                break

            raise e

        if n == 0:
            # We don't break here if it's stalling, but MockReader returns 0

            # and we check timeout above.

            pass

        else:
            out += buff.copy()

    return out^


fn _read_min_bytes[R: HTTPReader](mut conn: R, min_bytes: Int) raises -> Bytes:
    var out = Bytes()

    if min_bytes <= 0:
        return out^

    var buff = Bytes(capacity=default_buffer_size)

    while len(out) < min_bytes:
        var n: UInt

        try:
            n = conn.read(buff)

        except e:
            if String(e) == "EOF":
                break

            raise e

        if n == 0:
            break

        out += buff.copy()

    if len(out) > min_bytes:
        out = out[0:min_bytes]

    return out^


fn _read_chunked_bytes[
    R: HTTPReader
](mut conn: R, payload: Bytes) raises -> Bytes:
    var out = payload.copy()

    var buff = Bytes(capacity=default_buffer_size)

    while True:
        if len(out) >= 5:
            if (
                out[-5] == byte("0")
                and out[-4] == byte("\r")
                and out[-3] == byte("\n")
                and out[-2] == byte("\r")
                and out[-1] == byte("\n")
            ):
                break

        var n = conn.read(buff)

        if n == 0:
            break

        out += buff.copy()

    return out^


fn _read_response[
    R: HTTPReader
](mut conn: R, initial: Bytes) raises -> HTTPResponse:
    var reader = ByteReader(initial)
    var headers = Headers()
    var cookies = ResponseCookieJar()
    var protocol: String
    var status_code: String
    var status_text: String
    try:
        var properties = headers.parse_raw(reader)
        protocol, status_code, status_text = (
            properties[0],
            properties[1],
            properties[2],
        )
        cookies.from_headers(properties[3])
        reader.skip_carriage_return()
    except e:
        raise Error("Failed to parse response headers: " + String(e))

    var response = HTTPResponse(
        Bytes(),
        headers=headers,
        cookies=cookies,
        protocol=protocol,
        status_code=Int(status_code),
        status_text=status_text,
    )

    var transfer_encoding = response.headers.get(HeaderKey.TRANSFER_ENCODING)
    if transfer_encoding and transfer_encoding.value() == "chunked":
        var b = reader.read_bytes().to_bytes()
        var all = _read_chunked_bytes(conn, b)
        response.read_chunks(all)
        return response^

    var content_length = response.headers.content_length()
    if response.headers.get(HeaderKey.CONTENT_LENGTH) or content_length > 0:
        var body = reader.read_bytes().to_bytes()
        if len(body) < content_length:
            var extra = _read_min_bytes(conn, content_length - len(body))
            if len(extra) > 0:
                body += extra^
        if len(body) > content_length:
            body = body[0:content_length]
        var body_reader = ByteReader(body)
        response.read_body(body_reader)
        return response^

    var remaining = reader.read_bytes().to_bytes()
    if len(remaining) > 0:
        var remaining_len = len(remaining)
        response.body_raw = remaining^
        response.set_content_length(remaining_len)
        return response^

    var extra = _read_until_eof(conn)
    if len(extra) > 0:
        var extra_len = len(extra)
        response.body_raw = extra^
        response.set_content_length(extra_len)
    return response^


fn _has_header_terminator(data: Bytes) -> Bool:
    if len(data) < 4:
        return False
    var i = 0
    while i + 3 < len(data):
        if (
            data[i] == byte("\r")
            and data[i + 1] == byte("\n")
            and data[i + 2] == byte("\r")
            and data[i + 3] == byte("\n")
        ):
            return True
        i += 1
    return False


struct HTTPSClient:
    var allow_redirects: Bool

    fn __init__(out self, allow_redirects: Bool = False):
        self.allow_redirects = allow_redirects

    fn do(mut self, var request: HTTPRequest) raises -> HTTPResponse:
        if request.uri.host == "":
            raise Error("HTTPSClient.do: Host must not be empty.")
        if not request.uri.is_https():
            raise Error("HTTPSClient.do: HTTPS URI required.")

        var port: UInt16
        if request.uri.port:
            port = request.uri.port.value()
        else:
            if request.uri.scheme == Scheme.HTTPS.value:
                port = 443
            else:
                raise Error(
                    "HTTPSClient.do: Invalid scheme received in the URI."
                )

        request.headers[HeaderKey.HOST] = request.uri.host
        request.headers["User-Agent"] = "ssl.mojo/0.1"

        var tls = connect_https(request.uri.host, port)
        var conn = TLSConnectionAdapter(tls^)

        var payload = encode(request.copy())
        while len(payload) > 0 and payload[len(payload) - 1] == byte("\0"):
            _ = payload.pop()
        try:
            _ = conn.write(payload)
        except e:
            conn.teardown()
            raise e

        var buf = Bytes(capacity=default_buffer_size)
        try:
            _ = conn.read(buf)
        except e:
            conn.teardown()
            raise e
        var initial = buf.copy()
        while not _has_header_terminator(initial):
            var more = Bytes(capacity=default_buffer_size)
            var n = conn.read(more)
            if n == 0:
                break
            initial += more.copy()

        var response = _read_response(conn, initial)

        if self.allow_redirects and response.is_redirect():
            conn.teardown()
            return self._handle_redirect(request^, response^)

        conn.teardown()
        return response^

    fn _handle_redirect(
        mut self,
        var original_request: HTTPRequest,
        var original_response: HTTPResponse,
    ) raises -> HTTPResponse:
        var new_uri: URI
        var new_location: String
        try:
            new_location = original_response.headers[HeaderKey.LOCATION]
        except e:
            raise Error(
                "HTTPSClient._handle_redirect: `Location` header was not"
                " received in the response."
            )

        if new_location and new_location.startswith("http"):
            try:
                new_uri = URI.parse(new_location)
            except e:
                raise Error(
                    "HTTPSClient._handle_redirect: Failed to parse the new"
                    " URI: "
                    + String(e)
                )
            original_request.headers[HeaderKey.HOST] = new_uri.host
        else:
            new_uri = original_request.uri.copy()
            new_uri.path = new_location
        original_request.uri = new_uri^
        return self.do(original_request^)
