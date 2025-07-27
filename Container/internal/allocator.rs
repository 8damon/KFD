use std::{
    cell::UnsafeCell,
    ptr,
    sync::{atomic::AtomicU64, Once},
};
use winapi::{
    ctypes::c_void,
    um::{
        memoryapi::{VirtualAlloc, VirtualProtect},
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
    },
};

/// Bump‑pointer allocator for RWX memory regions.
///
/// The arena is backed by a single `VirtualAlloc` of the specified `size` with
/// `PAGE_EXECUTE_READWRITE` permissions. Individual allocations cannot be freed.
///
/// # Example
/// ```ignore
/// let mut arena = Arena::new(0x10000);
/// let ptr = arena.kfalloc(64, 16); // allocate 64 bytes aligned to 16 bytes
/// ```
pub struct Arena {
    base: *mut u8,
    offset: usize,
    size: usize,
}

unsafe impl Sync for Arena {}

impl Arena {
    /// Creates a new arena of `size` bytes with RWX permissions.
    ///
    /// # Panics
    /// Panics if `VirtualAlloc` fails to reserve the requested region.
    pub unsafe fn new(size: usize) -> Self {
        let ptr = VirtualAlloc(ptr::null_mut(), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            as *mut u8;
        if ptr.is_null() {
            panic!("Arena::new: VirtualAlloc failed");
        }
        Arena { base: ptr, offset: 0, size }
    }

    /// Allocates `len` bytes from the arena, aligned to `align`.
    ///
    /// # Parameters
    /// - `len`: Number of bytes to allocate.
    /// - `align`: Power‑of‑two alignment for the returned pointer.
    ///
    /// # Returns
    /// - Pointer to the aligned block, or null if out of memory.
    ///
    /// # Safety
    /// Caller must ensure `align` is a power of two.
    #[inline(always)]
    pub unsafe fn kfalloc(&mut self, len: usize, align: usize) -> *mut u8 {
        let cur = (self.base as usize).wrapping_add(self.offset);
        let aligned = (cur + (align - 1)) & !(align - 1);
        let used = aligned.wrapping_sub(self.base as usize).wrapping_add(len);
        if used > self.size {
            return ptr::null_mut();
        }
        self.offset = used;
        aligned as *mut u8
    }
}

// ===== Thread‑local Shadow Stack Allocator =====

const SHADOW_STACK_SIZE: usize = 0x4000;
const GUARD_PAGE_SIZE: usize   = 0x1000;
const ALIGNMENT_SLACK: usize   = 0x10;

/// Allocator for a per‑thread shadow stack with a guard page.
///
/// The first page of the region is marked `PAGE_NOACCESS` to catch stack underruns.
/// The usable stack is `SHADOW_STACK_SIZE` bytes, aligned to 16 bytes.
struct ShadowStackAllocator {
    /// Aligned top pointer of the shadow stack (stack grows downward).
    top: *mut u8,
}

unsafe impl Sync for ShadowStackAllocator {}

impl ShadowStackAllocator {
    /// Allocates a new shadow stack with guard page and returns its aligned top.
    ///
    /// # Returns
    /// - `Ok(Self)` with `top` set to the 16-byte aligned stack top.
    /// - `Err(1)` if allocation fails.
    ///
    /// # Safety
    /// Caller must respect guard page boundaries and only pivot the stack when preparing syscalls.
    unsafe fn new() -> Result<Self, u64> {
        let total = GUARD_PAGE_SIZE + SHADOW_STACK_SIZE + ALIGNMENT_SLACK;
        let raw = VirtualAlloc(ptr::null_mut(), total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            as *mut u8;
        if raw.is_null() {
            return Err(1);
        }

        let mut old = 0;
        let _ = VirtualProtect(raw as *mut c_void, GUARD_PAGE_SIZE, PAGE_NOACCESS, &mut old);

        let top = ((raw as usize + GUARD_PAGE_SIZE + SHADOW_STACK_SIZE) & !0xF) as *mut u8;
        Ok(ShadowStackAllocator { top })
    }
}

thread_local! {
    /// Thread‑local storage for each thread’s shadow stack allocator.
    static SHADOW_ALLOC: UnsafeCell<Option<ShadowStackAllocator>> = UnsafeCell::new(None);
}

/// Returns the 16‑byte aligned top of the calling thread’s shadow stack,
/// allocating it on first use.
///
/// # Returns
/// - `Ok(top_ptr)` on success.
/// - `Err(1)` if allocation fails.
///
/// # Safety
/// Must be used only in controlled stack pivots for syscall dispatch.
pub unsafe fn KfAllocShadowStack() -> Result<*mut u8, u64> {
    SHADOW_ALLOC.with(|cell| {
        let slot = &mut *cell.get();
        if slot.is_none() {
            *slot = Some(ShadowStackAllocator::new()?);
        }
        Ok(slot.as_ref().unwrap().top)
    })
}

/// Lazily initialized singleton arena for all trampoline allocations.
pub struct StaticArena {
    once: Once,
    inner: UnsafeCell<Option<Arena>>,
}

unsafe impl Sync for StaticArena {}

impl StaticArena {
    /// Creates a new `StaticArena` that will allocate on first use.
    pub const fn new() -> Self {
        StaticArena {
            once: Once::new(),
            inner: UnsafeCell::new(None),
        }
    }

    /// Returns a mutable pointer to the global `Arena`, initializing it if needed.
    ///
    /// # Safety
    /// - Must be called in a single‑threaded init context or externally synchronized.
    /// - Reentrant calls are not supported.
    pub unsafe fn get(&self, size: usize) -> *mut Arena {
        self.once.call_once(|| {
            *self.inner.get() = Some(Arena::new(size));
        });
        match &mut *self.inner.get() {
            Some(a) => a as *mut Arena,
            None => ptr::null_mut(),
        }
    }
}

/// Global trampoline arena for allocating RWX stubs.
pub static TRAMP_ARENA: StaticArena = StaticArena::new();

/// Global monotonic counter for LRU cache freshness tracking.
pub static TRAMP_TICK: AtomicU64 = AtomicU64::new(1);