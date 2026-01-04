"""Minimal ASN.1 DER reader helpers for X.509 parsing."""
from collections import List

@fieldwise_init
struct DerSlice:
    var tag: UInt8
    var start: Int
    var header_len: Int
    var len: Int

struct DerReader:
    var data: List[UInt8]
    var offset: Int

    fn __init__(out self, in_data: List[UInt8]):
        self.data = in_data.copy()
        self.offset = 0

    fn remaining(self) -> Int:
        return len(self.data) - self.offset

    fn peek_tag(self) -> UInt8:
        if self.offset >= len(self.data):
            return UInt8(0)
        return self.data[self.offset]

    fn read_u8(mut self) -> UInt8:
        var b = self.data[self.offset]
        self.offset += 1
        return b

    fn read_len(mut self) -> Int:
        var first = self.read_u8()
        if first < UInt8(0x80):
            return Int(first)
        var count = Int(first & UInt8(0x7f))
        var v = 0
        var i = 0
        while i < count:
            v = (v << 8) | Int(self.read_u8())
            i += 1
        return v

    fn read_tlv(mut self) -> DerSlice:
        var start = self.offset
        var tag = self.read_u8()
        var len = self.read_len()
        var header_len = self.offset - start
        self.offset += len
        return DerSlice(tag, start, header_len, len)

fn slice_bytes(data: List[UInt8], start: Int, length: Int) -> List[UInt8]:
    var out = List[UInt8]()
    var i = 0
    while i < length:
        out.append(data[start + i])
        i += 1
    return out^

fn read_sequence_reader(mut reader: DerReader) -> DerReader:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x30):
        return DerReader(List[UInt8]())
    var value = slice_bytes(reader.data, slice.start + slice.header_len, slice.len)
    return DerReader(value)

fn read_oid_bytes(mut reader: DerReader) -> List[UInt8]:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x06):
        return List[UInt8]()
    return slice_bytes(reader.data, slice.start + slice.header_len, slice.len)

fn read_integer_bytes(mut reader: DerReader) -> List[UInt8]:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x02):
        return List[UInt8]()
    var bytes = slice_bytes(reader.data, slice.start + slice.header_len, slice.len)
    # Trim leading zero for positive integers.
    if len(bytes) > 0 and bytes[0] == UInt8(0x00):
        var trimmed = List[UInt8]()
        var i = 1
        while i < len(bytes):
            trimmed.append(bytes[i])
            i += 1
        return trimmed^
    return bytes^

fn read_bit_string(mut reader: DerReader) -> List[UInt8]:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x03):
        return List[UInt8]()
    var bytes = slice_bytes(reader.data, slice.start + slice.header_len, slice.len)
    if len(bytes) == 0:
        return List[UInt8]()
    var out = List[UInt8]()
    var i = 1
    while i < len(bytes):
        out.append(bytes[i])
        i += 1
    return out^

fn read_octet_string(mut reader: DerReader) -> List[UInt8]:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x04):
        return List[UInt8]()
    return slice_bytes(reader.data, slice.start + slice.header_len, slice.len)

fn read_any(mut reader: DerReader) -> List[UInt8]:
    var slice = reader.read_tlv()
    return slice_bytes(reader.data, slice.start, slice.header_len + slice.len)
