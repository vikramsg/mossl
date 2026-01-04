from collections import List

fn b64_char_to_val(c: StringSlice) -> Int:
    if c >= "A" and c <= "Z":
        return ord(c) - ord("A")
    if c >= "a" and c <= "z":
        return ord(c) - ord("a") + 26
    if c >= "0" and c <= "9":
        return ord(c) - ord("0") + 52
    if c == "+":
        return 62
    if c == "/":
        return 63
    return -1

fn base64_decode(encoded: String) -> List[UInt8]:
    var out = List[UInt8]()
    var buffer = 0
    var bits_collected = 0
    
    for i in range(len(encoded)):
        var c = encoded[i]
        if c == "=":
            break
        
        var val = b64_char_to_val(c)
        if val == -1:
            continue
            
        buffer = (buffer << 6) | val
        bits_collected += 6
        
        if bits_collected >= 8:
            bits_collected -= 8
            out.append(UInt8((buffer >> bits_collected) & 0xFF))
            
    return out^
