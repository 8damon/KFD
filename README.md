# KFD (Konflict)

**KFD**, like [ActiveBreach](https://github.com/dutchpsycho/ActiveBreach-Engine) is a ``syscall`` execution framework. This is a redux specialized for operating in heavily sandboxed/EDR-monitored environments.

### What's different?

The critical flaw with *ActiveBreach*, *SysWhispers* and other direct system-call frameworks is that they're super easily detected via a simple RIP/stack-unwind check and seeing that the return-address/IP is outside of ``ntdll.dll``, in process-mapped memory or random executable regions.

There's many ways around this but the most stable I've found is quite simply executing syscalls as intended by Windows but instead of routing through API's I ``jmp`` to the SSN stub directly, sidestepping any instrumentation or hooks. This results in the RIP looking normal and a stack unwind unless extremely advanced will categorize the call as normal.

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

## License

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**  

[Full License](https://creativecommons.org/licenses/by-nc/4.0/)

## Disclaimer
This tool is for educational and research use only. Use at your own risk. You are solely responsible for how you use this code.
