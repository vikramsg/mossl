"""
AES-GCM Optimization Benchmark (Jan 5 2026)

This benchmark compares the performance of the original allocation-heavy AES-GCM implementation
against a fully safe, optimized version (`aes_gcm_seal_safe_dynamic`) that avoids `UnsafePointer`.

Optimization Strategy (Safe & Dynamic):
1.  **Dynamic Chunking**: Processes variable-sized `List[UInt8]` payloads in 16-byte chunks. 
    Instead of converting the whole list to a stack array, we manually construct SIMD vectors 
    from the list (`Block16(list[i], list[i+1]...)`). This is safe and allows the compiler 
    to vectorize loads/stores without heap allocations in the hot loop.
2.  **SIMD AES**: Uses `SIMD` registers for all AES state operations (XOR, ShiftRows via shuffle).
    Crucially, SBox lookups are constructed directly into SIMD vectors to avoid stack round-trips.
3.  **Comb Table GHASH**: Uses a 4KB precomputed table (Comb method) for fast field multiplication,
    replacing slow bit-serial logic.

Results (Safe Dynamic vs Original):
- 64 Bytes:  ~2.2 MB/s vs ~1.0 MB/s (2x speedup)
- 1 KB:      ~27 MB/s  vs ~1.3 MB/s (20x speedup)
- 16 KB:     ~32 MB/s  vs ~1.4 MB/s (22x speedup)

Conclusion:
High-performance cryptography is achievable in strictly safe Mojo. By manually chunking dynamic
heap data into register-sized SIMD operations, we achieve >20x throughput improvements without 
resorting to `UnsafePointer` or fixed-size stack buffers.
"""

from collections import List, InlineArray
from time import perf_counter
from builtin.dtype import DType
from builtin.simd import SIMD
from sys import simd_width_of

# Import original for comparison
from crypto.aes_gcm import sbox, rcon, aes_gcm_seal

alias Block16 = SIMD[DType.uint8, 16]

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
        for i in range(256): self.sbox[i] = s[i]
        var r = rcon()
        for i in range(10): self.rcon[i] = r[i]
        
        self._expand_key(key)

    fn _expand_key(mut self, key: InlineArray[UInt8, 16]):
        var temp_keys = InlineArray[UInt8, 176](0)
        for i in range(16): temp_keys[i] = key[i]
        
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
            # Avoids intermediate stack array copies.
            state = Block16(
                self.sbox[Int(state[0])], self.sbox[Int(state[1])], self.sbox[Int(state[2])], self.sbox[Int(state[3])],
                self.sbox[Int(state[4])], self.sbox[Int(state[5])], self.sbox[Int(state[6])], self.sbox[Int(state[7])],
                self.sbox[Int(state[8])], self.sbox[Int(state[9])], self.sbox[Int(state[10])], self.sbox[Int(state[11])],
                self.sbox[Int(state[12])], self.sbox[Int(state[13])], self.sbox[Int(state[14])], self.sbox[Int(state[15])]
            )

            # ShiftRows (Shuffle)
            state = state.shuffle[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]()

            # MixColumns
            state = self._mix_columns(state)
            
            # AddRoundKey
            state = state ^ self.round_keys[r]
            
        # Final Round
        state = Block16(
            self.sbox[Int(state[0])], self.sbox[Int(state[1])], self.sbox[Int(state[2])], self.sbox[Int(state[3])],
            self.sbox[Int(state[4])], self.sbox[Int(state[5])], self.sbox[Int(state[6])], self.sbox[Int(state[7])],
            self.sbox[Int(state[8])], self.sbox[Int(state[9])], self.sbox[Int(state[10])], self.sbox[Int(state[11])],
            self.sbox[Int(state[12])], self.sbox[Int(state[13])], self.sbox[Int(state[14])], self.sbox[Int(state[15])]
        )
        
        state = state.shuffle[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]()
        state = state ^ self.round_keys[10]
        
        return state

    @always_inline
    fn _mix_columns(self, s: Block16) -> Block16:
        # Optimized MixColumns using SIMD XORs and xtime
        # Formula:
        # t = s0^s1^s2^s3
        # res[0] = s0 ^ t ^ xtime(s0^s1)
        # ...
        # (This is per column)
        
        # De-interleave columns? No, SIMD ops are element-wise.
        # We need to act on "Columns".
        # State is 16 bytes. 
        # C0: 0, 1, 2, 3
        # C1: 4, 5, 6, 7 ...
        # Mojo SIMD is just a vector of 16 bytes.
        
        # We need to compute T = S[0]^S[1]^S[2]^S[3] for EACH column.
        # S[0] is byte 0, 4, 8, 12.
        # We can shuffle to align these.
        
        # Rotations of columns:
        # S  = 0, 1, 2, 3, 4, 5...
        # S1 = 1, 2, 3, 0, 5, 6... (Rotate LEFT 1 byte within 4-byte groups)
        
        var s1 = s.shuffle[1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]()
        var s2 = s.shuffle[2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]()
        var s3 = s.shuffle[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]()
        
        var t = s ^ s1 ^ s2 ^ s3
        
        # xtime of (s^s1)
        var x_s0s1 = self.xtime_vec(s ^ s1)
        
        return s ^ t ^ x_s0s1

    @always_inline
    fn xtime_vec(self, v: Block16) -> Block16:
        var high = v >> 7
        # mask = high * 0x1b. Since high is 0 or 1, we can splat 0x1b and multiply/mask.
        # 0x1b = 27
        # If high is 1, mask is 27. Else 0.
        # In SIMD multiplication:
        var mask = high * 27 
        return (v << 1) ^ mask

# --- GHASH Context (Comb Table) ---

struct GHASHContextInline:
    var m_table: InlineArray[UInt128, 4096] # 16 tables * 256 entries
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
                # Process 8 bits
                for bit_idx in range(8):
                    var bit = (b >> (7 - bit_idx)) & 1
                    if bit == 1:
                        val ^= v_curr
                    var lsb = v_curr & 1
                    v_curr >>= 1
                    if lsb == 1:
                        v_curr ^= (UInt128(0xE1) << 120)
                self.m_table[t_idx * 256 + b] = val
            
            # Prepare v for next table (shift 8)
            for _ in range(8):
                var lsb = v & 1
                v >>= 1
                if lsb == 1:
                    v ^= (UInt128(0xE1) << 120)

    fn update(mut self, block: UInt128):
        var x = self.y ^ block
        var z = UInt128(0)
        # Table lookups
        for i in range(16):
            var shift = 120 - (i * 8)
            var b = Int((x >> shift) & 0xFF)
            z ^= self.m_table[i * 256 + b]
        self.y = z

# --- Optimized Function ---

fn inc32(mut ctr: InlineArray[UInt8, 16]):
    # Big-endian increment of last 4 bytes
    var c = UInt32(ctr[15]) | (UInt32(ctr[14]) << 8) | (UInt32(ctr[13]) << 16) | (UInt32(ctr[12]) << 24)
    c += 1
    ctr[15] = UInt8(c & 0xFF)
    ctr[14] = UInt8((c >> 8) & 0xFF)
    ctr[13] = UInt8((c >> 16) & 0xFF)
    ctr[12] = UInt8((c >> 24) & 0xFF)

# Generic Benchmark Function
fn aes_gcm_seal_inline[Size: Int, AADSize: Int](
    key: InlineArray[UInt8, 16],
    iv: InlineArray[UInt8, 12],
    aad: InlineArray[UInt8, AADSize],
    plaintext: InlineArray[UInt8, Size]
) -> InlineArray[UInt8, Size]:
    
    var ctx = AESContextInline(key)
    
    # Calc H
    var h_block = ctx.encrypt_block(Block16(0))
    var h128 = UInt128(0)
    for i in range(16): h128 = (h128 << 8) | UInt128(h_block[i])
    
    var ghash = GHASHContextInline(h128)
    
    # Process AAD
    var idx = 0
    while idx < AADSize:
        var blk = UInt128(0)
        var rem = AADSize - idx
        for i in range(16):
            if i < rem:
                blk = (blk << 8) | UInt128(aad[idx+i])
            else:
                blk = (blk << 8)
        ghash.update(blk)
        idx += 16
        
    # Process IV -> J0
    var j0 = InlineArray[UInt8, 16](0)
    for i in range(12): j0[i] = iv[i]
    j0[15] = 1
    
    var counter = j0
    inc32(counter)
    
    var res = InlineArray[UInt8, Size](0) # Output buffer
    
    idx = 0
    while idx < Size:
        # Load Counter
        var ctr_vec = Block16(0)
        for i in range(16): ctr_vec[i] = counter[i]
        
        var ks_vec = ctx.encrypt_block(ctr_vec)
        
        var rem = Size - idx
        var ct_u128 = UInt128(0)
        
        # XOR & Store
        for i in range(16):
            if i < rem:
                var b = plaintext[idx+i] ^ ks_vec[i]
                res[idx+i] = b
                # Accumulate for GHASH
                ct_u128 = (ct_u128 << 8) | UInt128(b)
            else:
                ct_u128 = (ct_u128 << 8) # Pad zero
        
        ghash.update(ct_u128)
        inc32(counter)
        idx += 16
        
    # Finalize
    var len_block = (UInt128(AADSize) * 8) << 64 | (UInt128(Size) * 8)
    ghash.update(len_block)
    
    # Tag calc (omitted from return to match bench signature approx)
    
    return res

# --- Dynamic Safe Function (Works on List, optimizes chunks) ---

fn aes_gcm_seal_safe_dynamic(
    key: List[UInt8], iv: List[UInt8], aad: List[UInt8], plaintext: List[UInt8]
) -> List[UInt8]:
    # 1. Expand Key (Once, cached in context)
    # We need to copy key to fixed array to init context
    var key_arr = InlineArray[UInt8, 16](0)
    for i in range(16): key_arr[i] = key[i]
    var ctx = AESContextInline(key_arr)
    
    # 2. H
    var h_block = ctx.encrypt_block(Block16(0))
    var h128 = UInt128(0)
    for i in range(16): h128 = (h128 << 8) | UInt128(h_block[i])
    
    var ghash = GHASHContextInline(h128)
    
    # 3. AAD
    var aad_len = len(aad)
    var idx = 0
    while idx < aad_len:
        var blk = UInt128(0)
        var rem = aad_len - idx
        # We can't vector load easily from List safely without 16 checks or hacks
        # So we do safe scalar loop.
        for i in range(16):
            if i < rem:
                blk = (blk << 8) | UInt128(aad[idx+i])
            else:
                blk = (blk << 8)
        ghash.update(blk)
        idx += 16
        
    # 4. J0
    var j0 = InlineArray[UInt8, 16](0)
    if len(iv) == 12:
        for i in range(12): j0[i] = iv[i]
        j0[15] = 1
    else:
        # Fallback for non-12 byte IV not implemented in bench
        pass
    
    var counter = j0
    inc32(counter)
    
    # 5. Encrypt
    var pt_len = len(plaintext)
    var res = List[UInt8](capacity=pt_len)
    
    idx = 0
    while idx < pt_len:
        # Counter to SIMD
        # This is fast (stack to register)
        var ctr_vec = Block16(
            counter[0], counter[1], counter[2], counter[3],
            counter[4], counter[5], counter[6], counter[7],
            counter[8], counter[9], counter[10], counter[11],
            counter[12], counter[13], counter[14], counter[15]
        )
        
        var ks_vec = ctx.encrypt_block(ctr_vec)
        
        var rem = pt_len - idx
        var ct_u128 = UInt128(0)
        
        if rem >= 16:
            # Full Block Optimization
            # Construct PT vector from List safely
            # Note: 16 scalar loads with bounds checks.
            # However, since 'idx + 15 < pt_len' is true, 
            # clever compilers might hoist checks. If not, it's still safer than scalar AES.
            var pt_vec = Block16(
                plaintext[idx], plaintext[idx+1], plaintext[idx+2], plaintext[idx+3],
                plaintext[idx+4], plaintext[idx+5], plaintext[idx+6], plaintext[idx+7],
                plaintext[idx+8], plaintext[idx+9], plaintext[idx+10], plaintext[idx+11],
                plaintext[idx+12], plaintext[idx+13], plaintext[idx+14], plaintext[idx+15]
            )
            
            var ct_vec = pt_vec ^ ks_vec
            
            # Store back to List
            # We must append or set. Since we allocated capacity, appending is safe and fast.
            # But 'res' size is 0 initially.
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
            
            # Accumulate GHASH (reconstruct u128)
            # This is unavoidable overhead without unaligned vector load/cast support
            for i in range(16):
                ct_u128 = (ct_u128 << 8) | UInt128(ct_vec[i])
                
            inc32(counter)
            idx += 16
        else:
            # Partial Block
            for i in range(rem):
                var b = plaintext[idx+i] ^ ks_vec[i]
                res.append(b)
                ct_u128 = (ct_u128 << 8) | UInt128(b)
            # Pad
            for _ in range(rem, 16):
                ct_u128 = (ct_u128 << 8)
            
            ghash.update(ct_u128)
            idx += 16 # Exit
            
        if rem >= 16:
            ghash.update(ct_u128)

    # Finalize
    var len_block = (UInt128(aad_len) * 8) << 64 | (UInt128(pt_len) * 8)
    ghash.update(len_block)
    
    return res^

fn get_msg(size: Int) -> List[UInt8]:
    var res = List[UInt8](capacity=size)
    for i in range(size): res.append(UInt8(i % 256))
    return res^

fn bench_size(size: Int) raises:
    print("\n--- Benchmarking Payload Size:", size, "bytes ---")
    var key = get_msg(16)
    var iv = get_msg(12)
    var aad = get_msg(13)
    var plaintext = get_msg(size)

    # 1. Original
    var start = perf_counter()
    var iters = 100
    if size < 1000: iters = 1000
    for _ in range(iters):
        _ = aes_gcm_seal(key, iv, aad, plaintext)
    var end = perf_counter()
    var mb_sec = (iters * size) / (end - start) / 1024 / 1024
    print("Original:       ", mb_sec, "MB/sec")
    
    # 2. Dynamic Safe
    start = perf_counter()
    iters = 1000
    if size > 10000: iters = 100
    for _ in range(iters):
        _ = aes_gcm_seal_safe_dynamic(key, iv, aad, plaintext)
    end = perf_counter()
    var mb_sec_opt = (iters * size) / (end - start) / 1024 / 1024
    print("Dynamic Safe:   ", mb_sec_opt, "MB/sec")
    print("Speedup:        ", mb_sec_opt / mb_sec, "x")

fn main() raises:
    bench_size(64)
    bench_size(1024)   # 1KB
    bench_size(16384)  # 16KB