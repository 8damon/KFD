use std::arch::asm;

#[inline(always)]
pub unsafe fn hash_name(name: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xCBF29CE484222325;
    const FNV_PRIME:  u64 = 0x100000001B3;
    const ENTROPY_SEED: u64 = 0xA5A5_A5A5_A5A5_A5A5;

    let mut hash: u64 = FNV_OFFSET ^ ENTROPY_SEED.rotate_left(17);
    let ptr = name.as_ptr();
    let len = name.len();
    let mut offset = 0;

    while offset + 16 <= len {
        let mut block: [u8; 16] = [0; 16];
        std::ptr::copy_nonoverlapping(ptr.add(offset), block.as_mut_ptr(), 16);

        let mut chunk_hash: u64;
        asm!(
            "movdqu xmm0, [{block}]",
            "movq rax, xmm0",
            "psrldq xmm0, 8",
            "movq rcx, xmm0",
            "xor rax, rcx",
            "xor rax, {hash}",
            "imul rax, {prime}",
            block = in(reg) block.as_ptr(),
            hash = in(reg) hash,
            prime = in(reg) FNV_PRIME,
            out("rax") chunk_hash,
            out("rcx") _,
            out("xmm0") _,
        );
        hash = chunk_hash.rotate_left(5) ^ chunk_hash.rotate_right(3);
        offset += 16;
    }

    while offset < len {
        let byte = *ptr.add(offset);
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        hash = hash.rotate_left(5) ^ hash.rotate_right(3);
        offset += 1;
    }

    let len = len as u64;
    hash ^= len.wrapping_mul(0x9E3779B97F4A7C15);
    hash ^= (hash >> 33) ^ (hash << 29);
    hash
}