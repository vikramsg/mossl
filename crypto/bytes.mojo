"""Byte helpers for hex parsing and formatting."""
from collections import List

fn hex_nibble(ch: StringSlice) -> UInt8:
    if ch == "0":
        return UInt8(0)
    if ch == "1":
        return UInt8(1)
    if ch == "2":
        return UInt8(2)
    if ch == "3":
        return UInt8(3)
    if ch == "4":
        return UInt8(4)
    if ch == "5":
        return UInt8(5)
    if ch == "6":
        return UInt8(6)
    if ch == "7":
        return UInt8(7)
    if ch == "8":
        return UInt8(8)
    if ch == "9":
        return UInt8(9)
    if ch == "a" or ch == "A":
        return UInt8(10)
    if ch == "b" or ch == "B":
        return UInt8(11)
    if ch == "c" or ch == "C":
        return UInt8(12)
    if ch == "d" or ch == "D":
        return UInt8(13)
    if ch == "e" or ch == "E":
        return UInt8(14)
    if ch == "f" or ch == "F":
        return UInt8(15)
    return UInt8(0)

fn hex_to_bytes(hex: String) -> List[UInt8]:
    var out = List[UInt8]()
    var i = 0
    while i < len(hex):
        var hi = hex_nibble(hex[i])
        var lo = hex_nibble(hex[i + 1])
        out.append(UInt8((hi << 4) | lo))
        i += 2
    return out^

fn bytes_to_hex(bytes: List[UInt8]) -> String:
    var digits = "0123456789abcdef"
    var out = ""
    for b in bytes:
        var hi = Int((b >> 4) & 0x0f)
        var lo = Int(b & 0x0f)
        out += digits[hi] + digits[lo]
    return out^

fn concat_bytes(a: List[UInt8], b: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    for v in a:
        out.append(v)
    for v in b:
        out.append(v)
    return out^

fn zeros(count: Int) -> List[UInt8]:
    var out = List[UInt8]()
    var i = 0
    while i < count:
        out.append(UInt8(0))
        i += 1
    return out^
