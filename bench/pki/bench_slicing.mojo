from collections import List
from testing import assert_equal
import time

# --- Current Implementation (Copying) ---

@fieldwise_init
struct DerSliceCopy:
    var tag: UInt8
    var start: Int
    var header_len: Int
    var len: Int

struct DerReaderCopy:
    var data: List[UInt8]
    var offset: Int

    fn __init__(out self, in_data: List[UInt8]):
        self.data = in_data.copy()
        self.offset = 0

    fn read_u8(mut self) raises -> UInt8:
        var b = self.data[self.offset]
        self.offset += 1
        return b

    fn read_len(mut self) raises -> Int:
        var first = self.read_u8()
        if first < UInt8(0x80): return Int(first)
        var count = Int(first & UInt8(0x7F))
        var v = 0
        for _ in range(count):
            v = (v << 8) | Int(self.read_u8())
        return v

    fn read_tlv(mut self) raises -> DerSliceCopy:
        var start = self.offset
        var tag = self.read_u8()
        var length = self.read_len()
        var header_len = self.offset - start
        if self.offset + length > len(self.data):
             raise Error("ASN1: TLV length exceeds data")
        self.offset += length
        return DerSliceCopy(tag, start, header_len, length)

fn slice_bytes_copy(data: List[UInt8], start: Int, length: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=length)
    for i in range(length):
        out.append(data[start + i])
    return out.copy()

# --- Proposed Implementation (Zero-Copy using borrowed List and offsets) ---

@fieldwise_init
struct DerSliceZero:
    var tag: UInt8
    var start: Int
    var header_len: Int
    var len: Int

struct ByteViewZero(ImplicitlyCopyable, Copyable):
    var offset: Int
    var length: Int

    fn __init__(out self, offset: Int, length: Int):
        self.offset = offset
        self.length = length

    fn __copyinit__(out self, other: ByteViewZero):
        self.offset = other.offset
        self.length = other.length

struct DerReaderZero:
    var offset: Int
    var view: ByteViewZero

    fn __init__(out self, view: ByteViewZero):
        self.view = view
        self.offset = 0

    fn read_u8(mut self, data: List[UInt8]) raises -> UInt8:
        if self.offset >= self.view.length:
            raise Error("EOF")
        var b = data[self.view.offset + self.offset]
        self.offset += 1
        return b

    fn read_len(mut self, data: List[UInt8]) raises -> Int:
        var first = self.read_u8(data)
        if first < UInt8(0x80): return Int(first)
        var count = Int(first & UInt8(0x7F))
        var v = 0
        for _ in range(count):
            v = (v << 8) | Int(self.read_u8(data))
        return v

    fn read_tlv(mut self, data: List[UInt8]) raises -> DerSliceZero:
        var start = self.offset
        var tag = self.read_u8(data)
        var length = self.read_len(data)
        var header_len = self.offset - start
        if self.offset + length > self.view.length:
             raise Error("ASN1: TLV length exceeds data (Zero)")
        self.offset += length
        return DerSliceZero(tag, start, header_len, length)

fn slice_bytes_zero(view: ByteViewZero, start: Int, length: Int) -> ByteViewZero:
    return ByteViewZero(view.offset + start, length)

# --- Benchmark Logic ---

fn create_large_mock_cert() -> List[UInt8]:
    var data = List[UInt8]()
    # Let's create a large SEQUENCE manually to avoid length encoding issues
    # Total items: 100 small sequences of 10 bytes each = 1000 bytes
    data.append(0x30)
    data.append(0x82)
    data.append(0x03) # 0x03E8 = 1000
    data.append(0xE8)
    
    for _ in range(100):
        data.append(0x30)
        data.append(8)
        for _ in range(8):
            data.append(UInt8(0))
    return data^

fn test_correctness() raises:
    var data = create_large_mock_cert()
    
    # Test Copying
    var reader_c = DerReaderCopy(data)
    var seq_c = reader_c.read_tlv()
    var inner_data_c = slice_bytes_copy(data, seq_c.start + seq_c.header_len, seq_c.len)
    var inner_reader_c = DerReaderCopy(inner_data_c)
    var int_c = inner_reader_c.read_tlv()
    var int_bytes_c = slice_bytes_copy(inner_reader_c.data, int_c.start + int_c.header_len, int_c.len)
    
    # Test Zero-Copy
    var view_z = ByteViewZero(0, len(data))
    var reader_z = DerReaderZero(view_z)
    var seq_z = reader_z.read_tlv(data)
    var inner_view_z = slice_bytes_zero(view_z, seq_z.start + seq_z.header_len, seq_z.len)
    var inner_reader_z = DerReaderZero(inner_view_z)
    var int_z = inner_reader_z.read_tlv(data)
    var int_view_z = slice_bytes_zero(inner_view_z, int_z.start + int_z.header_len, int_z.len)
    
    assert_equal(len(int_bytes_c), int_view_z.length)
    for i in range(len(int_bytes_c)):
        var val_z = data[int_view_z.offset + i]
        assert_equal(Int(int_bytes_c[i]), Int(val_z))
    print("Correctness check passed.")

fn run_bench_copy(data: List[UInt8], iterations: Int) raises:
    var start_time = time.perf_counter()
    for _ in range(iterations):
        var reader = DerReaderCopy(data)
        var seq = reader.read_tlv()
        var inner_data = slice_bytes_copy(data, seq.start + seq.header_len, seq.len)
        var inner_reader = DerReaderCopy(inner_data)
        while inner_reader.offset < len(inner_reader.data):
            var tlv = inner_reader.read_tlv()
            # Simulate field extraction
            var slice = slice_bytes_copy(inner_reader.data, tlv.start + tlv.header_len, tlv.len)
            _ = len(slice)
    var end_time = time.perf_counter()
    print("Copying:   ", (end_time - start_time) / 1_000_000, "ms")

fn run_bench_zero(data: List[UInt8], iterations: Int) raises:
    var start_time = time.perf_counter()
    for _ in range(iterations):
        var view = ByteViewZero(0, len(data))
        var reader = DerReaderZero(view)
        var seq = reader.read_tlv(data)
        var inner_view = slice_bytes_zero(view, seq.start + seq.header_len, seq.len)
        var inner_reader = DerReaderZero(inner_view)
        while inner_reader.offset < inner_view.length:
            var tlv = inner_reader.read_tlv(data)
            # Simulate field extraction
            var slice = slice_bytes_zero(inner_view, tlv.start + tlv.header_len, tlv.len)
            _ = slice.length
    var end_time = time.perf_counter()
    print("Zero-Copy: ", (end_time - start_time) / 1_000_000, "ms")

fn main() raises:
    test_correctness()
    var data = create_large_mock_cert()
    var iterations = 10_000
    print("Iterations:", iterations)
    run_bench_copy(data, iterations)
    run_bench_zero(data, iterations)