use crate::printdev;
use crate::internal::{
    allocator::KfAllocShadowStack,
    resolver::{KfInitializeSyscallMaps, resolve_syscall_stub},
    bridge::KfFetchOrCreateBridge,
};

/// Number of arguments passed via registers (RCX, RDX, R8, R9) on x64 Windows.
///
/// Any additional arguments (5th–16th) are placed onto a manually allocated shadow stack.
pub const MAX_REGISTER_ARGS: usize = 4;

/// Starts the Konflict syscall subsystem.
///
/// This must be called once before issuing any syscalls.
/// Performs:
/// 1. Scanning `ntdll.dll` exports for valid syscall stubs.
/// 2. Building caches for resolver and integrity checks.
/// 3. Spawning a background thread for optional keep-alive or presence detection.
///
/// # Returns
/// - `Ok(())` if initialization succeeds.
/// - `Err(code)` if export scanning or map setup fails (nonzero u64).
///
/// # Safety
/// - Must be invoked at process startup, before any `KfDispatchSyscall` calls.
/// - Not inherently thread-safe; synchronize externally if calling concurrently.
#[inline(always)]
pub unsafe fn KfInitializeDispatcher() -> Result<(), u64> {
    KfInitializeSyscallMaps()?;

    let _ = std::thread::Builder::new()
        .spawn(|| {
            printdev!("[DBG] Konflict idle thread started");
            loop {
                std::thread::park(); // passive thread
            }
        });

    Ok(())
}

/// Dispatches a native NT syscall by name with up to 16 `u64` arguments.
///
/// Arguments 1–4 are passed via RCX, RDX, R8, and R9.
/// Arguments 5–16 are pushed onto the per-thread shadow stack in reverse order.
///
/// A trampoline is created on first use and cached for subsequent calls.
///
/// # Parameters
/// - `name`: The exact syscall name string (e.g., `"NtQueryVirtualMemory"`).
/// - `args`: A slice of up to 16 `u64` arguments.
///
/// # Returns
/// - `Ok(retval)` with the raw `RAX` return value if the syscall stub was invoked.
/// - `Err(status)` with a small integer code if dispatching failed:
///   - `1` → too many arguments, unknown syscall, trampoline allocation failure,
///           or shadow stack allocation failure.
///
/// # Example
/// ```ignore
/// unsafe {
///     let res = KfDispatchSyscall("NtYieldExecution", &[]);
///     match res {
///         Ok(0) => println!("Yielded successfully"),
///         Ok(code) => println!("Yield returned status: {}", code),
///         Err(_) => eprintln!("Dispatch error"),
///     }
/// }
/// ```
///
/// # Safety
/// - Caller must have invoked [`KfInitializeDispatcher()`] successfully before.
/// - Caller is responsible for using the correct syscall signature and arguments.
/// - Stack and trampoline manipulation uses RWX memory and inline ASM.
#[inline(always)]
pub unsafe fn KfDispatchSyscall(name: &str, args: &[u64]) -> Result<u64, u32> {
    if args.len() > 16 {
        printdev!("[DBG] KfDispatchSyscall: too many args for `{}`", name);
        return Err(1);
    }

    // Leak the name for static lifetime to key our caches
    let static_name: &'static str = Box::leak(name.to_owned().into_boxed_str());

    // Resolve or error out
    let stub_ptr = match resolve_syscall_stub(static_name) {
        Some(ptr) => ptr,
        None => {
            printdev!("[DBG] KfDispatchSyscall: unknown syscall `{}`", name);
            return Err(1);
        }
    };

    // Create or fetch trampoline
    let trampoline = KfFetchOrCreateBridge(static_name, stub_ptr);
    if trampoline.is_null() {
        printdev!("[ERR] KfDispatchSyscall: trampoline alloc failed for `{}`", name);
        return Err(1);
    }

    // Allocate per-thread shadow stack
    let shadow_top = match KfAllocShadowStack() {
        Ok(p) => p as usize,
        Err(_) => {
            printdev!("[ERR] KfDispatchSyscall: shadow stack alloc failed");
            return Err(1);
        }
    };

    // Build downward-growing stack for arguments beyond the 4th
    let mut shadow_rsp = shadow_top & !0xF;
    for &arg in args.iter().skip(MAX_REGISTER_ARGS).rev() {
        shadow_rsp -= 8;
        *(shadow_rsp as *mut u64) = arg;
    }

    // Pivot stack and invoke syscall
    let orig_rsp: usize;
    core::arch::asm!("mov {}, rsp", out(reg) orig_rsp);
    core::arch::asm!("mov rsp, {}", in(reg) shadow_rsp);

    let result: u64;
    core::arch::asm! {
        "mov r10, rcx",
        "call rax",
        in("rax") trampoline,
        in("rcx") args.get(0).copied().unwrap_or(0),
        in("rdx") args.get(1).copied().unwrap_or(0),
        in("r8")  args.get(2).copied().unwrap_or(0),
        in("r9")  args.get(3).copied().unwrap_or(0),
        lateout("rax") result,
        clobber_abi("C"),
    }

    // Restore original stack pointer
    core::arch::asm!("mov rsp, {}", in(reg) orig_rsp);

    Ok(result)
}