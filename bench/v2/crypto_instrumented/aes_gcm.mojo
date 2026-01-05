"""AES-128 GCM implementation for TLS 1.3 record protection.
Optimized using SIMD, InlineArray, and precomputed tables.
Instrumented for profiling.
"""

from builtin.dtype import DType
from builtin.simd import SIMD
from collections import List, InlineArray
from sys import simd_width_of
from time import perf_counter

alias Block16 = SIMD[DType.uint8, 16]

struct Timer:
    var start: Float64
    var name: String

    fn __init__(out self, name: String):
        self.name = name
        self.start = perf_counter()

    fn stop(self):
        var end = perf_counter()
        print("    [AES-TIMER] " + self.name + ": " + String(end - self.start) + "s")

# --- Tables ---


fn sbox() -> InlineArray[UInt8, 256]:
    var s = InlineArray[UInt8, 256](0)
    # Populate S-Box (copied from standard values)
    var vals = List[UInt8](
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )
    for i in range(256):
        s[i] = vals[i]
    return s


fn rcon() -> InlineArray[UInt8, 10]:
    var r = InlineArray[UInt8, 10](0)
    var vals = List[UInt8](
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    )
    for i in range(10):
        r[i] = vals[i]
    return r


# --- AES Context (SIMD) ---


struct AESContextInline(Movable):
    var sbox: InlineArray[UInt8, 256]
    var rcon: InlineArray[UInt8, 10]
    var round_keys: InlineArray[Block16, 11]

    fn __init__(out self, key: InlineArray[UInt8, 16]):
        self.sbox = InlineArray[UInt8, 256](0)
        self.rcon = InlineArray[UInt8, 10](0)
        self.round_keys = InlineArray[Block16, 11](Block16(0))

        # Cache SBox & Rcon
        var s = sbox()
        for i in range(256):
            self.sbox[i] = s[i]
        var r = rcon()
        for i in range(10):
            self.rcon[i] = r[i]

        self._expand_key(key)

    fn _expand_key(mut self, key: InlineArray[UInt8, 16]):
        var temp_keys = InlineArray[UInt8, 176](0)
        for i in range(16):
            temp_keys[i] = key[i]

        var i = 16
        var rcon_idx = 0
        var temp = InlineArray[UInt8, 4](0)

        while i < 176:
            temp[0] = temp_keys[i - 4]
            temp[1] = temp_keys[i - 3]
            temp[2] = temp_keys[i - 2]
            temp[3] = temp_keys[i - 1]

            if (i % 16) == 0:
                # RotWord
                var t0 = temp[0]
                temp[0] = temp[1]
                temp[1] = temp[2]
                temp[2] = temp[3]
                temp[3] = t0

                # SubWord
                temp[0] = self.sbox[Int(temp[0])]
                temp[1] = self.sbox[Int(temp[1])]
                temp[2] = self.sbox[Int(temp[2])]
                temp[3] = self.sbox[Int(temp[3])]

                # Rcon
                temp[0] ^= self.rcon[rcon_idx]
                rcon_idx += 1

            for j in range(4):
                temp_keys[i] = temp_keys[i - 16] ^ temp[j]
                i += 1

        # Pack into SIMD
        for r in range(11):
            var vec = Block16(0)
            for j in range(16):
                vec[j] = temp_keys[r * 16 + j]
            self.round_keys[r] = vec

    fn encrypt_block(self, in_vec: Block16) -> Block16:
        var state = in_vec ^ self.round_keys[0]

        for r in range(1, 10):
            # SubBytes (Optimized: Direct scalar extraction and reconstruction)
            state = Block16(
                self.sbox[Int(state[0])],
                self.sbox[Int(state[1])],
                self.sbox[Int(state[2])],
                self.sbox[Int(state[3])],
                self.sbox[Int(state[4])],
                self.sbox[Int(state[5])],
                self.sbox[Int(state[6])],
                self.sbox[Int(state[7])],
                self.sbox[Int(state[8])],
                self.sbox[Int(state[9])],
                self.sbox[Int(state[10])],
                self.sbox[Int(state[11])],
                self.sbox[Int(state[12])],
                self.sbox[Int(state[13])],
                self.sbox[Int(state[14])],
                self.sbox[Int(state[15])],
            )

            # ShiftRows (Shuffle)
            state = state.shuffle[
                0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
            ]()

            # MixColumns
            state = self._mix_columns(state)

            # AddRoundKey
            state = state ^ self.round_keys[r]

        # Final Round
        state = Block16(
            self.sbox[Int(state[0])],
            self.sbox[Int(state[1])],
            self.sbox[Int(state[2])],
            self.sbox[Int(state[3])],
            self.sbox[Int(state[4])],
            self.sbox[Int(state[5])],
            self.sbox[Int(state[6])],
            self.sbox[Int(state[7])],
            self.sbox[Int(state[8])],
            self.sbox[Int(state[9])],
            self.sbox[Int(state[10])],
            self.sbox[Int(state[11])],
            self.sbox[Int(state[12])],
            self.sbox[Int(state[13])],
            self.sbox[Int(state[14])],
            self.sbox[Int(state[15])],
        )

        state = state.shuffle[
            0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
        ]()
        state = state ^ self.round_keys[10]

        return state

    @always_inline
    fn _mix_columns(self, s: Block16) -> Block16:
        # Optimized MixColumns
        var s1 = s.shuffle[
            1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
        ]()
        var s2 = s.shuffle[
            2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13
        ]()
        var s3 = s.shuffle[
            3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
        ]()

        var t = s ^ s1 ^ s2 ^ s3
        var x_s0s1 = self.xtime_vec(s ^ s1)
        return s ^ t ^ x_s0s1

    @always_inline
    fn xtime_vec(self, v: Block16) -> Block16:
        var high = v >> 7
        var mask = high * 27
        return (v << 1) ^ mask


# --- GHASH Context (Comb Table) ---


struct GHASHContextInline:
    var m_table: InlineArray[UInt128, 4096]
    var y: UInt128

    fn __init__(out self, h: UInt128):
        self.m_table = InlineArray[UInt128, 4096](0)
        self.y = UInt128(0)

        # Initialize tables (Comb method)
        var v = h
        for t_idx in range(16):
            var v_start = v
            for b in range(256):
                var val = UInt128(0)
                var v_curr = v_start
                for bit_idx in range(8):
                    var bit = (b >> (7 - bit_idx)) & 1
                    if bit == 1:
                        val ^= v_curr
                    var lsb = v_curr & 1
                    v_curr >>= 1
                    if lsb == 1:
                        v_curr ^= UInt128(0xE1) << 120
                self.m_table[t_idx * 256 + b] = val

            for _ in range(8):
                var lsb = v & 1
                v >>= 1
                if lsb == 1:
                    v ^= UInt128(0xE1) << 120

    fn update(mut self, block: UInt128):
        var x = self.y ^ block
        var z = UInt128(0)
        for i in range(16):
            var shift = 120 - (i * 8)
            var b = Int((x >> shift) & 0xFF)
            z ^= self.m_table[i * 256 + b]
        self.y = z


# --- Helpers ---


fn inc32(mut ctr: InlineArray[UInt8, 16]):
    var c = (
        UInt32(ctr[15])
        | (UInt32(ctr[14]) << 8)
        | (UInt32(ctr[13]) << 16)
        | (UInt32(ctr[12]) << 24)
    )
    c += 1
    ctr[15] = UInt8(c & 0xFF)
    ctr[14] = UInt8((c >> 8) & 0xFF)
    ctr[13] = UInt8((c >> 16) & 0xFF)
    ctr[12] = UInt8((c >> 24) & 0xFF)


# --- Public API ---


fn aes_encrypt_block(key: List[UInt8], block: List[UInt8]) -> List[UInt8]:
    var k_arr = InlineArray[UInt8, 16](0)
    for i in range(16):
        k_arr[i] = key[i]
    var ctx = AESContextInline(k_arr)

    var b_vec = Block16(0)
    for i in range(16):
        b_vec[i] = block[i]

    var out_vec = ctx.encrypt_block(b_vec)

    var out = List[UInt8]()
    for i in range(16):
        out.append(out_vec[i])
    return out^


fn aes_gcm_seal(
    key: List[UInt8], iv: List[UInt8], aad: List[UInt8], plaintext: List[UInt8]
) -> (List[UInt8], List[UInt8]):
    var t = Timer("aes_gcm_seal")
    # 1. Expand Key
    var key_arr = InlineArray[UInt8, 16](0)
    for i in range(16):
        key_arr[i] = key[i]
    var ctx = AESContextInline(key_arr)

    # 2. H
    var h_block = ctx.encrypt_block(Block16(0))
    var h128 = UInt128(0)
    for i in range(16):
        h128 = (h128 << 8) | UInt128(h_block[i])

    # 3. J0
    var j0 = InlineArray[UInt8, 16](0)
    if len(iv) == 12:
        for i in range(12):
            j0[i] = iv[i]
        j0[15] = 1
    else:
        var ghash_iv = GHASHContextInline(h128)
        var iv_len = len(iv)
        var i_idx = 0
        while i_idx < iv_len:
            var blk = UInt128(0)
            var rem = iv_len - i_idx
            for i in range(16):
                if i < rem:
                    blk = (blk << 8) | UInt128(iv[i_idx + i])
                else:
                    blk = blk << 8
            ghash_iv.update(blk)
            i_idx += 16
        var len_block = UInt128(iv_len) * 8
        ghash_iv.update(len_block)
        var y = ghash_iv.y
        for i in range(16):
            var shift = (15 - i) * 8
            j0[i] = UInt8((y >> shift) & 0xFF)

    # 4. GHASH for data
    var ghash = GHASHContextInline(h128)

    # Process AAD
    var aad_len = len(aad)
    var idx = 0
    while idx < aad_len:
        var blk = UInt128(0)
        var rem = aad_len - idx
        for i in range(16):
            if i < rem:
                blk = (blk << 8) | UInt128(aad[idx + i])
            else:
                blk = blk << 8
        ghash.update(blk)
        idx += 16

    # 5. Encrypt & Process CT
    var counter = j0
    inc32(counter)

    var pt_len = len(plaintext)
    var res = List[UInt8](capacity=pt_len)

    idx = 0
    while idx < pt_len:
        var ctr_vec = Block16(
            counter[0],
            counter[1],
            counter[2],
            counter[3],
            counter[4],
            counter[5],
            counter[6],
            counter[7],
            counter[8],
            counter[9],
            counter[10],
            counter[11],
            counter[12],
            counter[13],
            counter[14],
            counter[15],
        )

        var ks_vec = ctx.encrypt_block(ctr_vec)

        var rem = pt_len - idx
        var ct_u128 = UInt128(0)

        if rem >= 16:
            var pt_vec = Block16(
                plaintext[idx],
                plaintext[idx + 1],
                plaintext[idx + 2],
                plaintext[idx + 3],
                plaintext[idx + 4],
                plaintext[idx + 5],
                plaintext[idx + 6],
                plaintext[idx + 7],
                plaintext[idx + 8],
                plaintext[idx + 9],
                plaintext[idx + 10],
                plaintext[idx + 11],
                plaintext[idx + 12],
                plaintext[idx + 13],
                plaintext[idx + 14],
                plaintext[idx + 15],
            )
            var ct_vec = pt_vec ^ ks_vec

            res.append(ct_vec[0])
            res.append(ct_vec[1])
            res.append(ct_vec[2])
            res.append(ct_vec[3])
            res.append(ct_vec[4])
            res.append(ct_vec[5])
            res.append(ct_vec[6])
            res.append(ct_vec[7])
            res.append(ct_vec[8])
            res.append(ct_vec[9])
            res.append(ct_vec[10])
            res.append(ct_vec[11])
            res.append(ct_vec[12])
            res.append(ct_vec[13])
            res.append(ct_vec[14])
            res.append(ct_vec[15])

            for i in range(16):
                ct_u128 = (ct_u128 << 8) | UInt128(ct_vec[i])

            ghash.update(ct_u128)
            inc32(counter)
            idx += 16
        else:
            for i in range(rem):
                var b = plaintext[idx + i] ^ ks_vec[i]
                res.append(b)
                ct_u128 = (ct_u128 << 8) | UInt128(b)
            for _ in range(rem, 16):
                ct_u128 = ct_u128 << 8

            ghash.update(ct_u128)
            idx += 16

    # Finalize GHASH
    var len_block = (UInt128(aad_len) * 8) << 64 | (UInt128(pt_len) * 8)
    ghash.update(len_block)

    # Tag
    var j0_vec = Block16(
        j0[0],
        j0[1],
        j0[2],
        j0[3],
        j0[4],
        j0[5],
        j0[6],
        j0[7],
        j0[8],
        j0[9],
        j0[10],
        j0[11],
        j0[12],
        j0[13],
        j0[14],
        j0[15],
    )
    var ek_j0 = ctx.encrypt_block(j0_vec)
    var ek_j0_u128 = UInt128(0)
    for i in range(16):
        ek_j0_u128 = (ek_j0_u128 << 8) | UInt128(ek_j0[i])

    var tag_u128 = ghash.y ^ ek_j0_u128
    var tag = List[UInt8]()
    for i in range(16):
        var shift = (15 - i) * 8
        tag.append(UInt8((tag_u128 >> shift) & 0xFF))

    t.stop()
    return (res^, tag^)


fn aes_gcm_open(
    key: List[UInt8],
    iv: List[UInt8],
    aad: List[UInt8],
    ciphertext: List[UInt8],
    tag: List[UInt8],
) -> (List[UInt8], Bool):
    var t = Timer("aes_gcm_open")
    # 1. Expand Key
    var key_arr = InlineArray[UInt8, 16](0)
    for i in range(16):
        key_arr[i] = key[i]
    var ctx = AESContextInline(key_arr)

    # 2. H
    var h_block = ctx.encrypt_block(Block16(0))
    var h128 = UInt128(0)
    for i in range(16):
        h128 = (h128 << 8) | UInt128(h_block[i])

    # 3. J0
    var j0 = InlineArray[UInt8, 16](0)
    if len(iv) == 12:
        for i in range(12):
            j0[i] = iv[i]
        j0[15] = 1
    else:
        var ghash_iv = GHASHContextInline(h128)
        var iv_len = len(iv)
        var i_idx = 0
        while i_idx < iv_len:
            var blk = UInt128(0)
            var rem = iv_len - i_idx
            for i in range(16):
                if i < rem:
                    blk = (blk << 8) | UInt128(iv[i_idx + i])
                else:
                    blk = blk << 8
            ghash_iv.update(blk)
            i_idx += 16
        var len_block = UInt128(iv_len) * 8
        ghash_iv.update(len_block)
        var y = ghash_iv.y
        for i in range(16):
            var shift = (15 - i) * 8
            j0[i] = UInt8((y >> shift) & 0xFF)

    # 4. GHASH(AAD || CT || Len)
    var ghash = GHASHContextInline(h128)

    var aad_len = len(aad)
    var idx = 0
    while idx < aad_len:
        var blk = UInt128(0)
        var rem = aad_len - idx
        for i in range(16):
            if i < rem:
                blk = (blk << 8) | UInt128(aad[idx + i])
            else:
                blk = blk << 8
        ghash.update(blk)
        idx += 16

    var ct_len = len(ciphertext)
    idx = 0
    while idx < ct_len:
        var blk = UInt128(0)
        var rem = ct_len - idx
        for i in range(16):
            if i < rem:
                blk = (blk << 8) | UInt128(ciphertext[idx + i])
            else:
                blk = blk << 8
        ghash.update(blk)
        idx += 16

    var len_block = (UInt128(aad_len) * 8) << 64 | (UInt128(ct_len) * 8)
    ghash.update(len_block)

    # 5. Check Tag
    var j0_vec = Block16(
        j0[0],
        j0[1],
        j0[2],
        j0[3],
        j0[4],
        j0[5],
        j0[6],
        j0[7],
        j0[8],
        j0[9],
        j0[10],
        j0[11],
        j0[12],
        j0[13],
        j0[14],
        j0[15],
    )
    var ek_j0 = ctx.encrypt_block(j0_vec)
    var ek_j0_u128 = UInt128(0)
    for i in range(16):
        ek_j0_u128 = (ek_j0_u128 << 8) | UInt128(ek_j0[i])

    var calculated_tag_u128 = ghash.y ^ ek_j0_u128

    # Verify
    var tag_valid = True
    if len(tag) != 16:
        tag_valid = False
    else:
        var input_tag_u128 = UInt128(0)
        for i in range(16):
            input_tag_u128 = (input_tag_u128 << 8) | UInt128(tag[i])
        if input_tag_u128 != calculated_tag_u128:
            tag_valid = False

    if not tag_valid:
        t.stop()
        return (List[UInt8](), False)

    # 6. Decrypt
    var counter = j0
    inc32(counter)
    var res = List[UInt8](capacity=ct_len)

    idx = 0
    while idx < ct_len:
        var ctr_vec = Block16(
            counter[0],
            counter[1],
            counter[2],
            counter[3],
            counter[4],
            counter[5],
            counter[6],
            counter[7],
            counter[8],
            counter[9],
            counter[10],
            counter[11],
            counter[12],
            counter[13],
            counter[14],
            counter[15],
        )

        var ks_vec = ctx.encrypt_block(ctr_vec)

        var rem = ct_len - idx
        if rem >= 16:
            var ct_vec = Block16(
                ciphertext[idx],
                ciphertext[idx + 1],
                ciphertext[idx + 2],
                ciphertext[idx + 3],
                ciphertext[idx + 4],
                ciphertext[idx + 5],
                ciphertext[idx + 6],
                ciphertext[idx + 7],
                ciphertext[idx + 8],
                ciphertext[idx + 9],
                ciphertext[idx + 10],
                ciphertext[idx + 11],
                ciphertext[idx + 12],
                ciphertext[idx + 13],
                ciphertext[idx + 14],
                ciphertext[idx + 15],
            )
            var pt_vec = ct_vec ^ ks_vec
            for i in range(16):
                res.append(pt_vec[i])
            inc32(counter)
            idx += 16
        else:
            for i in range(rem):
                res.append(ciphertext[idx + i] ^ ks_vec[i])
            idx += 16

    t.stop()
    return (res^, True)