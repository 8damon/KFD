#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]

use core::ffi::c_char;
use core::slice;
use std::ffi::CStr;
use winapi::shared::minwindef::{DWORD, LPVOID};

mod internal;

use internal::dispatch::{KfInitializeDispatcher, KfDispatchSyscall};

/// TLS callback function that runs once on DLL_PROCESS_ATTACH.
///
/// This will not run on thread creation or detach.
#[no_mangle]
unsafe extern "system" fn TLS_CALLBACK_KF(_h: LPVOID, reason: DWORD, _reserved: LPVOID) {
    const DLL_PROCESS_ATTACH: DWORD = 1;
    if reason == DLL_PROCESS_ATTACH {
        let _ = KfInitializeDispatcher();
    }
}



/// Entrypoint used for invoking syscalls from FFI.
///
/// # Safety
/// - `name` must be a valid null-terminated C string.
/// - `args` must point to at least `argc` u64s.
#[no_mangle]
pub unsafe extern "C" fn kf_call(name: *const c_char, args: *const u64, argc: usize) -> u64 {
    if name.is_null() || args.is_null() || argc > 16 {
        return 0;
    }

    let cstr = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let args_slice = slice::from_raw_parts(args, argc);
    match KfDispatchSyscall(cstr, args_slice) {
        Ok(val) => val,
        Err(_) => 0,
    }
}