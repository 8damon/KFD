# KONFLICT

> **Konflict** is an altered version of [ActiveBreach](https://github.com/dutchpsycho/ActiveBreach-Engine), it addresses the critical limitation in traditional techniques like **ActiveBreach**, **SysWhispers**, and **DirectSyscall** all of which execute ``syscalls`` from process executable memory. While effective against average AV/EDR, these approaches fail under enterprise-grade EDR's/AV's that trace syscall stacks or verify caller addresses.

### What's different?

*ActiveBreach*, *SysWhispers*, *DirectSyscall* & a bunch of other implementations all map syscall prologue to stubs & execute from there. That'll work for basic EDR/AV but it's fragile as all it takes is a syscall trace or a caller address check to be uncovered.

So, how do you fix that? You don't wanna touch hooks, you don't want to patch anything and invalidate memory, but you need the call to originate from ntdll.dll, just like a real syscall would. My first idea was something *HellsGate* style: overwrite a legit syscall prologue with the SSN (Syscall Service Number) I want. Problem is, that breaks real function calls and destabilizes ntdll.dll. I can do better.

Then I figured maybe just extend on ntdll's .text section & embed a syscall stub, technically works, but it’s sloppy. Any callstack check would expose this, API called & export address wouldn't line up. Also thought of stack spoofing, overwiting return addresses and fixing the frame, but that won't change the original captured values.

Eventually I realized: Why not just use what’s already there? All the real Nt* stubs follow the same prologue because they have to, x64 syscall ABI demands it. Hooks might wrap them, but the syscall prologue itself doesn’t change. If I walk all Nt* exports and scan for the actual syscall instruction sequence I can jump directly into those instructions and completely sidestep hooks.

That’s what **Konflict** does. For every syscall, it builds a small encrypted bridge, not a full stub, just a minimal jump into the legit ntdll prologue. It decrypts, jumps in, and leaves zero trace outside of what a normal call would look like. No RWX stubs hanging around. No post-stack spoofing, No suspicious caller addresses. Just clean, indirect syscall execution, from the source!

## FFI Usage (From C or External Language)

You can dynamically load the compiled `konflict.dll` and call `kf_call` directly:

```c
extern uint64_t kf_call(const char* name, const uint64_t* args, size_t argc);

uint64_t args[2] = {
    (uint64_t)GetCurrentProcess(),
    (uint64_t)GetCurrentProcessId()
};

uint64_t result = kf_call("NtQueryInformationProcess", args, 2);
```

## Usage in Native Rust Projects

Add it as a subcrate or dependency in a workspace.

```toml
[dependencies]
Konflict = { path = "../Konflict" }
```

Then use the public API:

```rust
use Konflict::kf_call;

unsafe {
    let args = [
        GetCurrentProcess() as u64,
        GetCurrentProcessId() as u64,
    ];
    let result = kf_call(cstr!("NtQueryInformationProcess"), args.as_ptr(), args.len());
}
```

## Performance (As if it matters...)

Sample benchmark over 1,000,000 syscall invocations

```
[NtQueryVirtualMemory]
  → NT avg time     : 491ns
  → QA avg time     : 617ns
  → Overhead        : 25.66%

[NtWriteVirtualMemory]
  → NT avg time     : 440ns
  → QA avg time     : 589ns
  → Overhead        : 33.86%
```

This overhead is the cost of full bridge decryption, TLS stack setup, and syscall address validation, it remains well below the threshold of EDR heuristics and timing checks.

## License

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**  

[Full License](https://creativecommons.org/licenses/by-nc/4.0/)