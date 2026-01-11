"""Optimized Mojo AES-128 GCM implementation.
Uses InlineArray and SIMD for maximum performance and security.
"""

from builtin.dtype import DType
from builtin.simd import SIMD
from collections import List, InlineArray

from memory import Span

from crypto.bytes import constant_time_compare, zeroize

alias Block16 = SIMD[DType.uint8, 16]

# --- Tables ---


@always_inline
fn _sbox() -> InlineArray[UInt8, 256]:
    """Returns the AES S-Box."""
    var s = InlineArray[UInt8, 256](0)
    s[0] = 0x63
    s[1] = 0x7C
    s[2] = 0x77
    s[3] = 0x7B
    s[4] = 0xF2
    s[5] = 0x6B
    s[6] = 0x6F
    s[7] = 0xC5
    s[8] = 0x30
    s[9] = 0x01
    s[10] = 0x67
    s[11] = 0x2B
    s[12] = 0xFE
    s[13] = 0xD7
    s[14] = 0xAB
    s[15] = 0x76
    s[16] = 0xCA
    s[17] = 0x82
    s[18] = 0xC9
    s[19] = 0x7D
    s[20] = 0xFA
    s[21] = 0x59
    s[22] = 0x47
    s[23] = 0xF0
    s[24] = 0xAD
    s[25] = 0xD4
    s[26] = 0xA2
    s[27] = 0xAF
    s[28] = 0x9C
    s[29] = 0xA4
    s[30] = 0x72
    s[31] = 0xC0
    s[32] = 0xB7
    s[33] = 0xFD
    s[34] = 0x93
    s[35] = 0x26
    s[36] = 0x36
    s[37] = 0x3F
    s[38] = 0xF7
    s[39] = 0xCC
    s[40] = 0x34
    s[41] = 0xA5
    s[42] = 0xE5
    s[43] = 0xF1
    s[44] = 0x71
    s[45] = 0xD8
    s[46] = 0x31
    s[47] = 0x15
    s[48] = 0x04
    s[49] = 0xC7
    s[50] = 0x23
    s[51] = 0xC3
    s[52] = 0x18
    s[53] = 0x96
    s[54] = 0x05
    s[55] = 0x9A
    s[56] = 0x07
    s[57] = 0x12
    s[58] = 0x80
    s[59] = 0xE2
    s[60] = 0xEB
    s[61] = 0x27
    s[62] = 0xB2
    s[63] = 0x75
    s[64] = 0x09
    s[65] = 0x83
    s[66] = 0x2C
    s[67] = 0x1A
    s[68] = 0x1B
    s[69] = 0x6E
    s[70] = 0x5A
    s[71] = 0xA0
    s[72] = 0x52
    s[73] = 0x3B
    s[74] = 0xD6
    s[75] = 0xB3
    s[76] = 0x29
    s[77] = 0xE3
    s[78] = 0x2F
    s[79] = 0x84
    s[80] = 0x53
    s[81] = 0xD1
    s[82] = 0x00
    s[83] = 0xED
    s[84] = 0x20
    s[85] = 0xFC
    s[86] = 0xB1
    s[87] = 0x5B
    s[88] = 0x6A
    s[89] = 0xCB
    s[90] = 0xBE
    s[91] = 0x39
    s[92] = 0x4A
    s[93] = 0x4C
    s[94] = 0x58
    s[95] = 0xCF
    s[96] = 0xD0
    s[97] = 0xEF
    s[98] = 0xAA
    s[99] = 0xFB
    s[100] = 0x43
    s[101] = 0x4D
    s[102] = 0x33
    s[103] = 0x85
    s[104] = 0x45
    s[105] = 0xF9
    s[106] = 0x02
    s[107] = 0x7F
    s[108] = 0x50
    s[109] = 0x3C
    s[110] = 0x9F
    s[111] = 0xA8
    s[112] = 0x51
    s[113] = 0xA3
    s[114] = 0x40
    s[115] = 0x8F
    s[116] = 0x92
    s[117] = 0x9D
    s[118] = 0x38
    s[119] = 0xF5
    s[120] = 0xBC
    s[121] = 0xB6
    s[122] = 0xDA
    s[123] = 0x21
    s[124] = 0x10
    s[125] = 0xFF
    s[126] = 0xF3
    s[127] = 0xD2
    s[128] = 0xCD
    s[129] = 0x0C
    s[130] = 0x13
    s[131] = 0xEC
    s[132] = 0x5F
    s[133] = 0x97
    s[134] = 0x44
    s[135] = 0x17
    s[136] = 0xC4
    s[137] = 0xA7
    s[138] = 0x7E
    s[139] = 0x3D
    s[140] = 0x64
    s[141] = 0x5D
    s[142] = 0x19
    s[143] = 0x73
    s[144] = 0x60
    s[145] = 0x81
    s[146] = 0x4F
    s[147] = 0xDC
    s[148] = 0x22
    s[149] = 0x2A
    s[150] = 0x90
    s[151] = 0x88
    s[152] = 0x46
    s[153] = 0xEE
    s[154] = 0xB8
    s[155] = 0x14
    s[156] = 0xDE
    s[157] = 0x5E
    s[158] = 0x0B
    s[159] = 0xDB
    s[160] = 0xE0
    s[161] = 0x32
    s[162] = 0x3A
    s[163] = 0x0A
    s[164] = 0x49
    s[165] = 0x06
    s[166] = 0x24
    s[167] = 0x5C
    s[168] = 0xC2
    s[169] = 0xD3
    s[170] = 0xAC
    s[171] = 0x62
    s[172] = 0x91
    s[173] = 0x95
    s[174] = 0xE4
    s[175] = 0x79
    s[176] = 0xE7
    s[177] = 0xC8
    s[178] = 0x37
    s[179] = 0x6D
    s[180] = 0x8D
    s[181] = 0xD5
    s[182] = 0x4E
    s[183] = 0xA9
    s[184] = 0x6C
    s[185] = 0x56
    s[186] = 0xF4
    s[187] = 0xEA
    s[188] = 0x65
    s[189] = 0x7A
    s[190] = 0xAE
    s[191] = 0x08
    s[192] = 0xBA
    s[193] = 0x78
    s[194] = 0x25
    s[195] = 0x2E
    s[196] = 0x1C
    s[197] = 0xA6
    s[198] = 0xB4
    s[199] = 0xC6
    s[200] = 0xE8
    s[201] = 0xDD
    s[202] = 0x74
    s[203] = 0x1F
    s[204] = 0x4B
    s[205] = 0xBD
    s[206] = 0x8B
    s[207] = 0x8A
    s[208] = 0x70
    s[209] = 0x3E
    s[210] = 0xB5
    s[211] = 0x66
    s[212] = 0x48
    s[213] = 0x03
    s[214] = 0xF6
    s[215] = 0x0E
    s[216] = 0x61
    s[217] = 0x35
    s[218] = 0x57
    s[219] = 0xB9
    s[220] = 0x86
    s[221] = 0xC1
    s[222] = 0x1D
    s[223] = 0x9E
    s[224] = 0xE1
    s[225] = 0xF8
    s[226] = 0x98
    s[227] = 0x11
    s[228] = 0x69
    s[229] = 0xD9
    s[230] = 0x8E
    s[231] = 0x94
    s[232] = 0x9B
    s[233] = 0x1E
    s[234] = 0x87
    s[235] = 0xE9
    s[236] = 0xCE
    s[237] = 0x55
    s[238] = 0x28
    s[239] = 0xDF
    s[240] = 0x8C
    s[241] = 0xA1
    s[242] = 0x89
    s[243] = 0x0D
    s[244] = 0xBF
    s[245] = 0xE6
    s[246] = 0x42
    s[247] = 0x68
    s[248] = 0x41
    s[249] = 0x99
    s[250] = 0x2D
    s[251] = 0x0F
    s[252] = 0xB0
    s[253] = 0x54
    s[254] = 0xBB
    s[255] = 0x16
    return s


@always_inline
fn _rcon() -> InlineArray[UInt8, 10]:
    """Returns the AES RCON table."""
    return InlineArray[UInt8, 10](
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    )


struct AESContextInline(Movable):
    """AES-128 Encryption Context with non-allocating SIMD optimization."""

    var round_keys: InlineArray[Block16, 11]
    """The expanded round keys."""
    var sbox_vecs: InlineArray[Block16, 16]
    """Vectorized S-box for SIMD lookup."""

    fn __init__(out self, key: InlineArray[UInt8, 16]):
        """Initializes the context from a 16-byte key.

        Args:
            key: The 128-bit AES key.
        """
        self.round_keys = InlineArray[Block16, 11](fill=Block16(0))
        self.sbox_vecs = InlineArray[Block16, 16](fill=Block16(0))

        var s = _sbox()
        for i in range(16):
            var v = Block16(0)
            for j in range(16):
                v[j] = s[i * 16 + j]
            self.sbox_vecs[i] = v

        self._expand_key(key)

    fn _expand_key(mut self, key: InlineArray[UInt8, 16]):
        """AES key expansion logic."""
        var s = _sbox()
        var r = _rcon()
        var temp_keys = InlineArray[UInt8, 176](0)
        for i in range(16):
            temp_keys[i] = key[i]
        var i = 16
        var rcon_idx = 0
        var temp = InlineArray[UInt8, 4](0)
        while i < 176:
            for j in range(4):
                temp[j] = temp_keys[i - 4 + j]
            if (i % 16) == 0:
                var t0 = temp[0]
                temp[0] = s[Int(temp[1])] ^ r[rcon_idx]
                temp[1] = s[Int(temp[2])]
                temp[2] = s[Int(temp[3])]
                temp[3] = s[Int(t0)]
                rcon_idx += 1
            for j in range(4):
                temp_keys[i] = temp_keys[i - 16] ^ temp[j]
                i += 1
        for r_idx in range(11):
            var vec = Block16(0)
            for j in range(16):
                vec[j] = temp_keys[r_idx * 16 + j]
            self.round_keys[r_idx] = vec

    @always_inline
    fn _sbox_vec(self, state: Block16) -> Block16:
        """Vectorized constant-time S-Box lookup."""
        var out = Block16(0)
        var high_nibble = state >> 4
        var low_nibble = state & 0x0F
        for i in range(16):
            var chunk_idx = SIMD[DType.uint8, 16](UInt8(i))
            var mask_bool = high_nibble.eq(chunk_idx)
            var mask = mask_bool.select(Block16(0xFF), Block16(0x00))
            var lookups = self.sbox_vecs[i]._dynamic_shuffle(low_nibble)
            out |= mask & lookups
        return out

    fn encrypt_block(self, in_vec: Block16) -> Block16:
        """Encrypts a single 16-byte block.

        Args:
            in_vec: The 16-byte block to encrypt as a SIMD vector.

        Returns:
            The encrypted block.
        """
        var state = in_vec ^ self.round_keys[0]
        for r in range(1, 10):
            state = self._sbox_vec(state)
            state = state.shuffle[
                0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
            ]()
            state = self._mix_columns(state)
            state = state ^ self.round_keys[r]
        state = self._sbox_vec(state)
        state = state.shuffle[
            0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
        ]()
        state = state ^ self.round_keys[10]
        return state

    @always_inline
    fn _mix_columns(self, s: Block16) -> Block16:
        """AES MixColumns vectorized implementation."""
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
        """Vectorized Galois field multiplication by x."""
        var high = v >> 7
        var mask = high * 27
        return (v << 1) ^ mask

    fn zeroize(mut self):
        """Clears sensitive round keys from memory."""
        for i in range(11):
            self.round_keys[i] = Block16(0)


struct GHASHContextInline:
    """GHASH implementation for GCM authentication."""

    var m_table: InlineArray[UInt128, 4096]
    """Precomputed multiplication table."""
    var y: UInt128
    """Current GHASH state."""

    fn __init__(out self, h: UInt128):
        """Initializes the GHASH context with the hash key H.

        Args:
            h: The hash key derived from the AES key.
        """
        self.m_table = InlineArray[UInt128, 4096](fill=0)
        self.y = UInt128(0)
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
        """Updates the GHASH state with a new 16-byte block.

        Args:
            block: The 128-bit block to process.
        """
        var x = self.y ^ block
        var z = UInt128(0)
        for i in range(16):
            var b = Int((x >> (120 - (i * 8))) & 0xFF)
            z ^= self.m_table[i * 256 + b]
        self.y = z


@always_inline
fn _inc32(ctr_in: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
    """Increments the 32-bit counter part of the AES-GCM IV."""
    var ctr = ctr_in
    var c = (
        UInt32(ctr[15])
        | (UInt32(ctr[14]) << 8)
        | (UInt32(ctr[13]) << 16)
        | (UInt32(ctr[12]) << 24)
    ) + 1
    ctr[15] = UInt8(c & 0xFF)
    ctr[14] = UInt8((c >> 8) & 0xFF)
    ctr[13] = UInt8((c >> 16) & 0xFF)
    ctr[12] = UInt8((c >> 24) & 0xFF)
    return ctr


@fieldwise_init
struct AESGCMSealed(Movable):
    """Result of an AES-GCM seal operation."""

    var ciphertext: List[UInt8]
    """The encrypted data."""
    var tag: InlineArray[UInt8, 16]
    """The 16-byte authentication tag."""

    fn __moveinit__(out self, deinit other: Self):
        self.ciphertext = other.ciphertext^
        self.tag = other.tag


@fieldwise_init
struct AESGCMOpened(Movable):
    """Result of an AES-GCM open operation."""

    var plaintext: List[UInt8]
    """The decrypted data, empty if authentication failed."""
    var success: Bool
    """True if authentication succeeded."""

    fn __moveinit__(out self, deinit other: Self):
        self.plaintext = other.plaintext^
        self.success = other.success


fn aes_gcm_seal_internal(
    key: Span[UInt8], iv: Span[UInt8], aad: Span[UInt8], plaintext: Span[UInt8]
) raises -> AESGCMSealed:
    """Internal AES-GCM seal implementation (Public API)."""
    return _aes_gcm_seal_internal(key, iv, aad, plaintext)


fn aes_gcm_open_internal(
    key: Span[UInt8],
    iv: Span[UInt8],
    aad: Span[UInt8],
    ciphertext: Span[UInt8],
    tag: InlineArray[UInt8, 16],
) raises -> AESGCMOpened:
    """Internal AES-GCM open implementation (Public API)."""
    return _aes_gcm_open_internal(key, iv, aad, ciphertext, tag)


fn _aes_gcm_seal_internal(
    key: Span[UInt8], iv: Span[UInt8], aad: Span[UInt8], plaintext: Span[UInt8]
) raises -> AESGCMSealed:
    """Internal AES-GCM seal implementation."""
    if len(iv) == 0:
        raise Error("AES-GCM: IV length must be > 0")
    var key_arr = InlineArray[UInt8, 16](0)
    for i in range(16):
        key_arr[i] = key[i]
    var ctx = AESContextInline(key_arr)
    var h_block = ctx.encrypt_block(Block16(0))
    var h128 = UInt128(0)
    for i in range(16):
        h128 = (h128 << 8) | UInt128(h_block[i])
    var j0 = InlineArray[UInt8, 16](0)
    if len(iv) == 12:
        for i in range(12):
            j0[i] = iv[i]
        j0[15] = 1
    else:
        var ghash_iv = GHASHContextInline(h128)
        var i_idx = 0
        while i_idx < len(iv):
            var blk = UInt128(0)
            var rem = len(iv) - i_idx
            for i in range(16):
                blk <<= 8
                if i < rem:
                    blk |= UInt128(iv[i_idx + i])
            ghash_iv.update(blk)
            i_idx += 16
        ghash_iv.update(UInt128(len(iv)) * 8)
        var y = ghash_iv.y
        for i in range(16):
            j0[i] = UInt8((y >> ((15 - i) * 8)) & 0xFF)
    var ghash = GHASHContextInline(h128)
    var idx = 0
    while idx < len(aad):
        var blk = UInt128(0)
        var rem = len(aad) - idx
        for i in range(16):
            blk <<= 8
            if i < rem:
                blk |= UInt128(aad[idx + i])
        ghash.update(blk)
        idx += 16
    var ciphertext = List[UInt8](capacity=len(plaintext))
    for _ in range(len(plaintext)):
        ciphertext.append(0)
    var counter = j0
    counter = _inc32(counter)
    idx = 0
    while idx < len(plaintext):
        var ctr_vec = Block16(0)
        for i in range(16):
            ctr_vec[i] = counter[i]
        var ks_vec = ctx.encrypt_block(ctr_vec)
        var rem = len(plaintext) - idx
        var ct_u128 = UInt128(0)
        for i in range(16):
            var b = UInt8(0)
            if i < rem:
                b = plaintext[idx + i] ^ ks_vec[i]
                ciphertext[idx + i] = b
            ct_u128 = (ct_u128 << 8) | UInt128(b)
        ghash.update(ct_u128)
        counter = _inc32(counter)
        idx += 16
    ghash.update((UInt128(len(aad)) * 8) << 64 | (UInt128(len(plaintext)) * 8))
    var j0_vec = Block16(0)
    for i in range(16):
        j0_vec[i] = j0[i]
    var ek_j0 = ctx.encrypt_block(j0_vec)
    var tag = InlineArray[UInt8, 16](0)
    for i in range(16):
        tag[i] = UInt8((ghash.y >> ((15 - i) * 8)) & 0xFF) ^ ek_j0[i]
    ctx.zeroize()
    return AESGCMSealed(ciphertext^, tag)


fn _aes_gcm_open_internal(
    key: Span[UInt8],
    iv: Span[UInt8],
    aad: Span[UInt8],
    ciphertext: Span[UInt8],
    tag: InlineArray[UInt8, 16],
) raises -> AESGCMOpened:
    """Internal AES-GCM open implementation."""
    if len(iv) == 0:
        return AESGCMOpened(List[UInt8](), False)
    var key_arr = InlineArray[UInt8, 16](0)
    for i in range(16):
        key_arr[i] = key[i]
    var ctx = AESContextInline(key_arr)
    var h_block = ctx.encrypt_block(Block16(0))
    var h128 = UInt128(0)
    for i in range(16):
        h128 = (h128 << 8) | UInt128(h_block[i])
    var j0 = InlineArray[UInt8, 16](0)
    if len(iv) == 12:
        for i in range(12):
            j0[i] = iv[i]
        j0[15] = 1
    else:
        var ghash_iv = GHASHContextInline(h128)
        var i_idx = 0
        while i_idx < len(iv):
            var blk = UInt128(0)
            var rem = len(iv) - i_idx
            for i in range(16):
                blk <<= 8
                if i < rem:
                    blk |= UInt128(iv[i_idx + i])
            ghash_iv.update(blk)
            i_idx += 16
        ghash_iv.update(UInt128(len(iv)) * 8)
        var y = ghash_iv.y
        for i in range(16):
            j0[i] = UInt8((y >> ((15 - i) * 8)) & 0xFF)
    var ghash = GHASHContextInline(h128)
    var idx = 0
    while idx < len(aad):
        var blk = UInt128(0)
        var rem = len(aad) - idx
        for i in range(16):
            blk <<= 8
            if i < rem:
                blk |= UInt128(aad[idx + i])
        ghash.update(blk)
        idx += 16
    idx = 0
    while idx < len(ciphertext):
        var blk = UInt128(0)
        var rem = len(ciphertext) - idx
        for i in range(16):
            blk <<= 8
            if i < rem:
                blk |= UInt128(ciphertext[idx + i])
        ghash.update(blk)
        idx += 16
    ghash.update((UInt128(len(aad)) * 8) << 64 | (UInt128(len(ciphertext)) * 8))
    var j0_vec = Block16(0)
    for i in range(16):
        j0_vec[i] = j0[i]
    var ek_j0 = ctx.encrypt_block(j0_vec)
    var calc_tag = InlineArray[UInt8, 16](0)
    for i in range(16):
        calc_tag[i] = UInt8((ghash.y >> ((15 - i) * 8)) & 0xFF) ^ ek_j0[i]
    var tag_mojo = List[UInt8](capacity=16)
    var calc_tag_mojo = List[UInt8](capacity=16)
    for i in range(16):
        tag_mojo.append(tag[i])
        calc_tag_mojo.append(calc_tag[i])
    from crypto.bytes import constant_time_compare
    if not constant_time_compare(tag_mojo, calc_tag_mojo):
        ctx.zeroize()
        return AESGCMOpened(List[UInt8](), False)
    var plaintext = List[UInt8](capacity=len(ciphertext))
    for _ in range(len(ciphertext)):
        plaintext.append(0)
    var counter = j0
    counter = _inc32(counter)
    idx = 0
    while idx < len(ciphertext):
        var ctr_vec = Block16(0)
        for i in range(16):
            ctr_vec[i] = counter[i]
        var ks_vec = ctx.encrypt_block(ctr_vec)
        var rem = len(ciphertext) - idx
        for i in range(rem):
            if i < 16:
                plaintext[idx + i] = ciphertext[idx + i] ^ ks_vec[i]
        counter = _inc32(counter)
        idx += 16
    ctx.zeroize()
    return AESGCMOpened(plaintext^, True)


# Compatibility shims


fn aes_gcm_seal(
    key: List[UInt8], iv: List[UInt8], aad: List[UInt8], plaintext: List[UInt8]
) raises -> AESGCMSealed:
    """Compatibility shim for seal.





    Args:


        key: The 16-byte AES key.


        iv: The initialization vector.


        aad: Additional authenticated data.


        plaintext: The data to encrypt.





    Returns:


        The sealed result.


    """

    return _aes_gcm_seal_internal(
        Span(key), Span(iv), Span(aad), Span(plaintext)
    )


fn aes_gcm_open(
    key: List[UInt8],
    iv: List[UInt8],
    aad: List[UInt8],
    ciphertext: List[UInt8],
    tag: List[UInt8],
) raises -> AESGCMOpened:
    """Compatibility shim for open.





    Args:


        key: The 16-byte AES key.


        iv: The initialization vector.


        aad: Additional authenticated data.


        ciphertext: The data to decrypt.


        tag: The authentication tag.





    Returns:


        The opened result.


    """

    var tag_arr = InlineArray[UInt8, 16](0)

    for i in range(min(16, len(tag))):
        tag_arr[i] = tag[i]

    return _aes_gcm_open_internal(
        Span(key), Span(iv), Span(aad), Span(ciphertext), tag_arr
    )
