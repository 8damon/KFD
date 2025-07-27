//! NOTE: This is not cryptographically secure and is intended for memory obfuscation,
//! not data protection. Weak keying and round count are intentional for speed.

#![allow(non_snake_case)]
#![allow(dead_code)]

use core::arch::x86_64::{__cpuid, _rdtsc};

/// Number of 64-bit lanes in Keccak-f[1600] state.
const LANES: usize = 25;

/// Output block size in bytes (used as XOR chunk size).
pub const RATE: usize = 16;

/// Number of Keccak rounds to perform (reduced from 24 for speed).
const ROUNDS: usize = 4;

/// Round constants for Keccak-f[1600] permutation.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets for the ρ step in Keccak-f.
const RHO: [[u32; 5]; 5] = [
    [ 0, 36,  3, 41, 18 ],
    [ 1, 44, 10, 45,  2 ],
    [62,  6, 43, 15, 61 ],
    [28, 55, 25, 21, 56 ],
    [27, 20, 39,  8, 14 ],
];

/// Hardware-derived 128-bit session key using CPUID and TSC.
///
/// Used as entropy source for Keccak stream encryption.
/// Caches the key on first call for reuse.
///
/// # Returns
/// - `[u8; 16]`: 128-bit pseudo-unique session key.
fn session_key() -> [u8; 16] {
    static mut CACHED: Option<[u8; 16]> = None;
    unsafe {
        if let Some(k) = CACHED {
            return k;
        }

        let cpu = __cpuid(0);
        let tsc = _rdtsc();
        let mut k = [0u8; 16];

        k[0..4].copy_from_slice(&cpu.eax.to_le_bytes());
        k[4..8].copy_from_slice(&cpu.ebx.to_le_bytes());
        k[8..12].copy_from_slice(&(tsc as u32).to_le_bytes());
        k[12..16].copy_from_slice(&((tsc >> 32) as u32).to_le_bytes());

        CACHED = Some(k);
        k
    }
}

/// Reduced-round Keccak-f[1600] permutation core.
///
/// Applies the 5 standard steps: θ, ρ, π, χ, ι.
///
/// # Arguments
/// - `state`: The 25-lane (1600-bit) state to permute.
fn keccakf(state: &mut [u64; LANES]) {
    for round in 0..ROUNDS {
        // θ step
        let mut C = [0u64; 5];
        for x in 0..5 {
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        }

        let mut D = [0u64; 5];
        for x in 0..5 {
            D[x] = C[(x+4)%5] ^ C[(x+1)%5].rotate_left(1);
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x + 5*y] ^= D[x];
            }
        }

        // ρ and π steps
        let mut B = [0u64; LANES];
        for x in 0..5 {
            for y in 0..5 {
                let rotated = state[x + 5*y].rotate_left(RHO[y][x]);
                let (nx, ny) = (y, (2*x + 3*y) % 5);
                B[nx + 5*ny] = rotated;
            }
        }

        // χ step
        for x in 0..5 {
            for y in 0..5 {
                let i = x + 5*y;
                state[i] = B[i] ^ ((!B[((x+1)%5) + 5*y]) & B[((x+2)%5) + 5*y]);
            }
        }

        // ι step
        state[0] ^= RC[round];
    }
}

/// Generates a 16-byte keystream block based on internal state.
///
/// # Arguments
/// - `counter`: Unique block counter for stream.
/// - `out`: Output buffer to receive `RATE` bytes of XOR material.
fn keystream_block(counter: u64, out: &mut [u8; RATE]) {
    let mut state = [0u64; LANES];
    let k = session_key();

    state[0] = u64::from_le_bytes(k[0..8].try_into().unwrap());
    state[1] = u64::from_le_bytes(k[8..16].try_into().unwrap());
    state[2] = counter;

    keccakf(&mut state);

    out[0..8].copy_from_slice(&state[0].to_le_bytes());
    out[8..16].copy_from_slice(&state[1].to_le_bytes());
}

/// Applies Keccak stream cipher to a memory block using AVX2.
///
/// - Processes 64 bytes at a time via `_mm256_xor_si256`.
/// - Falls back to RATE (16B) chunking at tail.
/// - Encrypts or decrypts in-place (XOR-symmetric).
///
/// # Safety
/// - Caller must ensure `ptr` is valid and points to a writable region of `len` bytes.
/// - Requires AVX2 to be available on the host.
///
/// # Arguments
/// - `ptr`: Memory to encrypt/decrypt.
/// - `len`: Length of region to process.
#[target_feature(enable = "avx2")]
pub unsafe fn kcck_crypt_block(ptr: *mut u8, len: usize) {
    use core::arch::x86_64::*;

    let mut off = 0;
    let mut ctr = 0u64;
    let end = len.saturating_sub(64);

    while off <= end {
        let mut s = [0u64; LANES];
        let k = session_key();

        s[0] = u64::from_le_bytes(k[0..8].try_into().unwrap());
        s[1] = u64::from_le_bytes(k[8..16].try_into().unwrap());

        // Generate 4 blocks of 128-bit stream
        s[2] = ctr; keccakf(&mut s);
        let ks0 = _mm_set_epi64x(s[1] as i64, s[0] as i64); ctr += 1;

        s[2] = ctr; keccakf(&mut s);
        let ks1 = _mm_set_epi64x(s[1] as i64, s[0] as i64); ctr += 1;

        s[2] = ctr; keccakf(&mut s);
        let ks2 = _mm_set_epi64x(s[1] as i64, s[0] as i64); ctr += 1;

        s[2] = ctr; keccakf(&mut s);
        let ks3 = _mm_set_epi64x(s[1] as i64, s[0] as i64); ctr += 1;

        // Pack into 2x __m256i vectors (32B each)
        let k0 = _mm256_inserti128_si256(_mm256_castsi128_si256(ks0), ks1, 1);
        let k1 = _mm256_inserti128_si256(_mm256_castsi128_si256(ks2), ks3, 1);

        let dst = ptr.add(off) as *mut __m256i;
        let d0 = _mm256_loadu_si256(dst);
        let d1 = _mm256_loadu_si256(dst.add(1));

        let r0 = _mm256_xor_si256(d0, k0);
        let r1 = _mm256_xor_si256(d1, k1);

        _mm256_storeu_si256(dst, r0);
        _mm256_storeu_si256(dst.add(1), r1);

        off += 64;
    }

    // Tail: 16B chunks
    while off < len {
        let mut pad = [0u8; RATE];
        keystream_block(ctr, &mut pad);

        let chunk = core::cmp::min(RATE, len - off);
        let base = ptr.add(off);

        for i in 0..chunk {
            *base.add(i) ^= pad[i];
        }

        off += chunk;
        ctr += 1;
    }
}

/// Wrapper for decrypting memory using `kcck_crypt_block`.
///
/// Equivalent to `kcck_crypt_block(ptr, len)` since XOR is symmetric.
#[inline]
pub fn kcck_dcrypt_block(ptr: *mut u8, len: usize) {
    unsafe { kcck_crypt_block(ptr, len) }
}