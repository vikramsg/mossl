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

    fn read_u8(mut self) raises -> UInt8:
        if self.offset >= len(self.data):
            raise Error("ASN1: read past end of data")
        var b = self.data[self.offset]
        self.offset += 1
        return b

    fn read_len(mut self) raises -> Int:
        var first = self.read_u8()
        if first < UInt8(0x80):
            return Int(first)
        var count = Int(first & UInt8(0x7F))
        var v = 0
        var i = 0
        while i < count:
            v = (v << 8) | Int(self.read_u8())
            i += 1
        return v

    fn read_tlv(mut self) raises -> DerSlice:
        var start = self.offset
        var tag = self.read_u8()
        var length = self.read_len()
        var header_len = self.offset - start
        if self.offset + length > len(self.data):
            print(
                "ASN1 Debug: tag="
                + hex(Int(tag))
                + " start="
                + String(start)
                + " hlen="
                + String(header_len)
                + " length="
                + String(length)
                + " offset="
                + String(self.offset)
                + " data_len="
                + String(len(self.data))
            )
            raise Error("ASN1: TLV length exceeds data")
        self.offset += length
        return DerSlice(tag, start, header_len, length)


fn slice_bytes(data: List[UInt8], start: Int, length: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=length)
    for i in range(length):
        out.append(data[start + i])
    return out.copy()


fn read_sequence_reader(mut reader: DerReader) raises -> DerReader:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x30):
        return DerReader(List[UInt8]())
    return DerReader(
        slice_bytes(
            reader.data, slice.start + slice.header_len, slice.len
        ).copy()
    )


fn read_oid_bytes(mut reader: DerReader) raises -> List[UInt8]:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x06):
        return List[UInt8]()
    return slice_bytes(
        reader.data, slice.start + slice.header_len, slice.len
    ).copy()


fn read_integer_bytes(mut reader: DerReader) raises -> List[UInt8]:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x02):
        return List[UInt8]()
    var bytes = slice_bytes(
        reader.data, slice.start + slice.header_len, slice.len
    )
    if len(bytes) > 1 and bytes[0] == 0:
        var trimmed = List[UInt8](capacity=len(bytes) - 1)
        for i in range(1, len(bytes)):
            trimmed.append(bytes[i])
        return trimmed.copy()
    return bytes.copy()


fn read_bit_string(mut reader: DerReader) raises -> List[UInt8]:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x03):
        return List[UInt8]()
    var bytes = slice_bytes(
        reader.data, slice.start + slice.header_len, slice.len
    )
    if len(bytes) == 0:
        return List[UInt8]()
    var out = List[UInt8](capacity=len(bytes) - 1)
    for i in range(1, len(bytes)):
        out.append(bytes[i])
    return out.copy()


fn read_octet_string(mut reader: DerReader) raises -> List[UInt8]:
    var slice = reader.read_tlv()
    if slice.tag != UInt8(0x04):
        return List[UInt8]()
    return slice_bytes(
        reader.data, slice.start + slice.header_len, slice.len
    ).copy()
