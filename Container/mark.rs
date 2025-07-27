#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod internal;

use crate::internal::dispatch::{KfInitializeDispatcher, KfDispatchSyscall};

use std::time::{Duration, Instant};
use std::panic::{catch_unwind, AssertUnwindSafe};

use winapi::shared::basetsd::SIZE_T;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
use winapi::shared::ntdef::PVOID;
use winapi::um::winnt::HANDLE;


extern "system" {
    fn NtQueryVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        MemoryInformationClass: u32,
        MemoryInformation: PVOID,
        MemoryInformationLength: SIZE_T,
        ReturnLength: *mut SIZE_T,
    ) -> i32; // NTSTATUS

    fn NtWriteVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Buffer: PVOID,
        NumberOfBytesToWrite: SIZE_T,
        NumberOfBytesWritten: *mut SIZE_T,
    ) -> i32; // NTSTATUS
}

#[cfg(windows)]
#[link_section = ".CRT$XLB"]
#[used]
pub static TLS_CALLBACK: extern "C" fn(*mut u8, u32, *mut u8) = tls_callback;

#[cfg(windows)]
#[no_mangle]
pub extern "C" fn tls_callback(_dll_handle: *mut u8, reason: u32, _reserved: *mut u8) {
    const DLL_PROCESS_ATTACH: u32 = 1;

    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            if let Err(_) = KfInitializeDispatcher() {
                #[cfg(debug_assertions)]
                {
                    eprintln!("[TLS] Konflict start() failed: 0xFFFFFFFF");
                }
            }
        }
    }
}

fn avg_duration<F: FnMut()>(mut f: F, iterations: usize) -> Duration {
    let mut total: Duration = Duration::ZERO;

    for _ in 0..iterations {
        let start = Instant::now();

        let _ = catch_unwind(AssertUnwindSafe(&mut f)); // swallow panic

        total += start.elapsed();
    }

    total / iterations as u32
}

fn main() {
    const ITERS: usize = 1000000;

    unsafe {

        let process = GetCurrentProcess();
        let addr = main as *const () as usize as PVOID;

        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let mut retlen: SIZE_T = 0;

        let mut target: u32 = 0xDEADBEEF;
        let data: u32 = 0xCAFEBABE;
        let mut written: SIZE_T = 0;

        let native_query = || {
            let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            let mut retlen = 0usize;
            let _ = NtQueryVirtualMemory(
                process,
                addr,
                0,
                &mut mbi as *mut _ as PVOID,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
                &mut retlen as *mut _,
            );
        };

        let quanta_query = || {
            let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            let mut retlen = 0usize;
            let result = KfDispatchSyscall(
                "NtQueryVirtualMemory",
                &[
                    process as usize as u64,
                    addr as u64,
                    0,
                    &mut mbi as *mut _ as u64,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as u64,
                    &mut retlen as *mut _ as u64,
                ],
            );

            if let Err(code) = result {
                eprintln!("[!] QA_QUERY syscall failed: 0x{:08X}", code);
            }
        };

        let native_write = || {
            let mut target = 0xDEADBEEF_u32;
            let data = 0xCAFEBABE_u32;
            let mut written = 0usize;
            let _ = NtWriteVirtualMemory(
                process,
                &mut target as *mut _ as PVOID,
                &data as *const _ as PVOID,
                std::mem::size_of::<u32>() as SIZE_T,
                &mut written as *mut _,
            );
        };

        let quanta_write = || {
            let _ = KfDispatchSyscall(
                "NtWriteVirtualMemory",
                &[
                    process as usize as u64,
                    &mut target as *mut _ as u64,
                    &data as *const _ as u64,
                    std::mem::size_of::<u32>() as u64,
                    &mut written as *mut _ as u64,
                ],
            );
        };

        let native_q_time = avg_duration(native_query, ITERS);
        let quanta_q_time    = avg_duration(quanta_query,    ITERS);
        let native_w_time = avg_duration(native_write, ITERS);
        let quanta_w_time    = avg_duration(quanta_write,    ITERS);

        let nq_status = NtQueryVirtualMemory(
            process,
            addr,
            0,
            &mut mbi as *mut _ as PVOID,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
            &mut retlen as *mut _,
        );

        let nw_status = NtWriteVirtualMemory(
            process,
            &mut target as *mut _ as PVOID,
            &data as *const _ as PVOID,
            std::mem::size_of::<u32>() as SIZE_T,
            &mut written as *mut _,
        );

        fn overhead(native: Duration, quanta: Duration) -> f64 {
            let n = native.as_nanos() as f64;
            let r = quanta.as_nanos() as f64;

            if n == 0.0 {
                0.0
            } else {
                ((r - n) / n) * 100.0
            }
        }

        println!("====== Syscall Bench ({} reps) ======", ITERS);
        println!("[NtQueryVirtualMemory]");
        println!("  → NT avg time     : {:?}", native_q_time);
        println!("  → QA avg time     : {:?}", quanta_q_time);
        println!("  → Overhead        : {:.2}%", overhead(native_q_time, quanta_q_time));
        println!("  → NTSTATUS NT     : 0x{:08X}", nq_status as u32);
        println!("  → NTSTATUS QA     : 0x{:08X}", 0);

        println!();

        println!("[NtWriteVirtualMemory]");
        println!("  → NT avg time     : {:?}", native_w_time);
        println!("  → QA avg time     : {:?}", quanta_w_time);
        println!("  → Overhead        : {:.2}%", overhead(native_w_time, quanta_w_time));
        println!("  → Bytes written   : {}", written);
        println!("  → Mem value final : 0x{:08X}", target);
        println!("  → NTSTATUS NT     : 0x{:08X}", nw_status as u32);
        println!("  → NTSTATUS QA     : 0x{:08X}", 0);
        println!("======================================");        
    }
}