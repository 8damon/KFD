use std::{
    cell::UnsafeCell,
    ffi::{CStr, c_char},
    slice,
};

use rustc_hash::{FxBuildHasher, FxHashMap};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS};

use crate::printdev;

/// Internal mirror of the Windows `UNICODE_STRING` structure used
/// when traversing the PEB manually.
#[repr(C)]
struct UnicodeString {
    /// Length in bytes of the string stored in `Buffer`.
    Length: u16,
    /// Maximum capacity in bytes of `Buffer`.
    MaximumLength: u16,
    /// Pointer to a UTF-16 buffer.
    Buffer: *const u16,
}

/// Reads the current thread’s PEB pointer from `GS:[0x60]`.
///
/// # Safety
/// - Uses inline assembly to access `GS:[0x60]`.
/// - Relies on undocumented Windows internals and may break across OS versions.
#[inline(always)]
unsafe fn get_peb() -> *const u8 {
    let peb: *const u8;
    core::arch::asm!(
    "mov {}, gs:[0x60]",
    out(reg) peb,
    options(nostack, nomem, preserves_flags),
    );
    peb
}

/// Searches the PEB’s loader data for `ntdll.dll`, then validates
/// each candidate by scanning for known syscall stub patterns.
///
/// Returns the base address of the first matching module.
///
/// # Returns
/// - `Some(base)` if `ntdll.dll` with valid syscall stubs is found.
/// - `None` otherwise.
///
/// # Safety
/// - Reads raw pointers from the PEB/LDR structures.
/// - Does not use any safe Win32 APIs.
#[inline(always)]
pub unsafe fn KfGetNtdllBasePEB() -> Option<*const u8> {
    let peb = get_peb();
    let ldr = *(peb.add(0x18) as *const *const u8);
    let list = ldr.add(0x10) as *const *const u8;
    let head = *list;
    let mut current = head;

    // Walk up to 4 entries looking for ntdll exports
    for _ in 0..4 {
        let entry = current as *const u8;
        let dll_base = *(entry.add(0x30) as *const *const u8);

        if !dll_base.is_null() && KfScanSyscallPrologue(dll_base) {
            return Some(dll_base);
        }

        current = *(current as *const *const u8);
        if current == head {
            break;
        }
    }

    None
}

/// Scans a PE image at `base` for NT syscall stub signatures:
/// - `mov eax, imm32`
/// - `mov r10, rcx; mov eax, imm32`
///
/// Counts matches and returns `true` once a threshold is exceeded.
///
/// # Safety
/// - Assumes `base` is a valid, loaded PE image in memory.
#[inline(always)]
unsafe fn KfScanSyscallPrologue(base: *const u8) -> bool {
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D { return false; }

    let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
    if nt.Signature != 0x4550 { return false; }

    let export_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    if export_rva == 0 { return false; }

    let export = &*(base.add(export_rva) as *const IMAGE_EXPORT_DIRECTORY);
    let ords  = base.add(export.AddressOfNameOrdinals as usize) as *const u16;
    let funcs = base.add(export.AddressOfFunctions as usize) as *const u32;

    let mut matches = 0;
    for i in 0..export.NumberOfNames {
        let ord = *ords.add(i as usize) as usize;
        let ptr = base.add(*funcs.add(ord) as usize);
        let sig = slice::from_raw_parts(ptr, 8);

        if matches!(
            sig,
            [0xB8, ..]
            | [0x4C, 0x8B, 0xD1, 0xB8, ..]
            | [0x4D, 0x8B, 0xD1, 0xB8, ..]
        ) {
            matches += 1;
            if matches > 30 {
                return true;
            }
        }
    }

    false
}

/// Enumerates all NT syscall exports (names and addresses) from the PE image at `base`.
///
/// Only includes functions whose names start with `Nt` and whose first bytes match known syscall stubs.
///
/// # Returns
/// A `Vec` of tuples `(name, address)` for each valid syscall export.
///
/// # Safety
/// - Assumes `base` points to a valid, in-memory PE image.
#[inline(always)]
pub unsafe fn KfGetSyscallExports(base: *const u8) -> Vec<(&'static str, *const u8)> {
    let mut out = Vec::new();
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return out;
    }

    let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
    if nt.Signature != 0x4550 {
        return out;
    }

    let export = &*(base
        .add(nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize)
        as *const IMAGE_EXPORT_DIRECTORY);

    let names = base.add(export.AddressOfNames as usize) as *const u32;
    let ords  = base.add(export.AddressOfNameOrdinals as usize) as *const u16;
    let funcs = base.add(export.AddressOfFunctions as usize) as *const u32;

    for i in 0..export.NumberOfNames {
        let name_ptr = base.add(*names.add(i as usize) as usize) as *const c_char;
        let name_raw = CStr::from_ptr(name_ptr).to_bytes();
        if !name_raw.starts_with(b"Nt") {
            continue;
        }

        let ord = *ords.add(i as usize) as usize;
        let func_ptr = base.add(*funcs.add(ord) as usize);
        let sig = slice::from_raw_parts(func_ptr, 8);

        if matches!(
            sig,
            [0xB8, ..]
            | [0x4C, 0x8B, 0xD1, 0xB8, ..]
            | [0x4D, 0x8B, 0xD1, 0xB8, ..]
        ) {
            let name_str = core::str::from_utf8_unchecked(name_raw);
            printdev!("Found syscall: {} -> {:p}", name_str, func_ptr);
            out.push((name_str, func_ptr));
        }
    }

    out
}


/// A thread-safe static wrapper for an `Option<T>`, supporting interior mutability.
struct StaticOption<T>(UnsafeCell<Option<T>>);
unsafe impl<T> Sync for StaticOption<T> {}

/// Global cache of validated syscall addresses.
static SYSCALL_MAP: StaticOption<FxHashMap<&'static str, usize>> =
    StaticOption(UnsafeCell::new(None));

/// Shadow copy of original addresses, used for integrity checks.
static SHADOW_MAP: StaticOption<FxHashMap<&'static str, usize>> =
    StaticOption(UnsafeCell::new(None));

/// Initializes the syscall maps by locating `ntdll.dll` and scanning its exports.
///
/// Populates:
/// - `SYSCALL_MAP`: mapping from syscall name to address
/// - `SHADOW_MAP`: integrity-checked duplicate of addresses
///
/// # Errors
/// - Returns `Err(1)` if `ntdll.dll` cannot be found.
/// - Returns `Err(2)` if no valid exports are discovered.
///
/// # Safety
/// Must be called before any other syscall resolution routines.
pub unsafe fn KfInitializeSyscallMaps() -> Result<(), u32> {
    let base = match KfGetNtdllBasePEB() {
        Some(b) => b,
        None => return Err(1),
    };

    let exports = KfGetSyscallExports(base);
    if exports.is_empty() {
        return Err(2);
    }

    let mut map = FxHashMap::with_capacity_and_hasher(exports.len(), FxBuildHasher::default());
    let mut shadow = FxHashMap::with_capacity_and_hasher(exports.len(), FxBuildHasher::default());

    for (name, ptr) in exports {
        map.insert(name, ptr as usize);
        shadow.insert(name, ptr as usize);
    }

    *SYSCALL_MAP.0.get() = Some(map);
    *SHADOW_MAP.0.get() = Some(shadow);
    Ok(())
}

/// Resolves a cached syscall stub by name, verifying against the shadow map.
///
/// # Returns
/// - `Some(ptr)` if the syscall is found and integrity check passes.
/// - `None` otherwise.
///
/// # Safety
/// Caller must ensure `KfInitializeSyscallMaps()` has already succeeded.
#[inline(always)]
pub unsafe fn resolve_syscall_stub(name: &str) -> Option<*const u8> {
    let map = (*SYSCALL_MAP.0.get()).as_ref()?;
    let shadow = (*SHADOW_MAP.0.get()).as_ref()?;
    let addr = *map.get(name)? as usize;
    let guard = *shadow.get(name)? as usize;

    // Tampering detection
    if addr ^ guard != 0 {
        core::arch::asm!("int3", options(nomem, nostack));
        return None;
    }

    Some(addr as *const u8)
}

/// Looks up the raw export address of a syscall directly from `ntdll.dll`, bypassing cache.
///
/// # Returns
/// - `Some(ptr)` if the named export exists.
/// - `None` otherwise.
///
/// # Safety
/// Intended for debugging or verification; does not perform integrity checks.
#[inline(always)]
pub unsafe fn resolve_real_export(name: &str) -> Option<*const u8> {
    let base = KfGetNtdllBasePEB()?;
    for (n, ptr) in KfGetSyscallExports(base) {
        if n.eq_ignore_ascii_case(name) {
            return Some(ptr);
        }
    }
    None
}
