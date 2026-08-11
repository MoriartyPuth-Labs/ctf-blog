# Anti-Debugging & Anti-Analysis Bypasses

Detecting anti-debugging checks on Linux & Windows, patching binary checks, TLS callbacks, and Frida hooking bypasses.

***

### 1. Linux Anti-Debugging Techniques & Bypasses

#### 1.1 `ptrace(PTRACE_TRACEME)` Check

Only one process can trace a target via `ptrace`. Binaries call `ptrace(0, 0, 0, 0)` to detect if a debugger is attached.

**Patching `ptrace` in GDB / LD\_PRELOAD**

```bash
# Bypass via LD_PRELOAD shared library hook:
cat << 'EOF' > bypass_ptrace.c
long ptrace(int request, int pid, void *addr, void *data) {
    return 0; // Always return success!
}
EOF
gcc -shared -fPIC bypass_ptrace.c -o bypass_ptrace.so
LD_PRELOAD=./bypass_ptrace.so ./binary
```

```bash
# Bypass inside GDB:
catch syscall ptrace
commands
  set $rax = 0
  continue
end
```

***

#### 1.2 `/proc/self/status` TracerPID Check

Binaries read `/proc/self/status` and search for `TracerPID: <PID>`. If `<PID> != 0`, a debugger is attached.

**Bypass Strategy**

Patch the binary string from `"TracerPID"` to `"TracerXXX"` in hex editor or Ghidra so the search fails.

***

### 2. Windows Anti-Debugging Techniques & Bypasses

#### 2.1 Process Environment Block (PEB) Checks

* `BeingDebugged` flag at `PEB + 0x02`.
* `NtGlobalFlag` at `PEB + 0x68` (x64) / `0xBC` (x86).

**ScyllaHide / x64dbg Plugin**

Use **ScyllaHide** plugin in x64dbg to automatically hook and zero out PEB anti-debug flags.

#### 2.2 TLS Callbacks (Thread Local Storage)

TLS callbacks run **before the `main` or `EntryPoint` code executes**, allowing anti-debug checks to kill the process before your debugger breaks!

**GDB / x64dbg Setup**

In x64dbg or GDB, configure break options:

* Break on `TLS Callbacks` or `System Breakpoint` before `EntryPoint`.

***

### 3. Frida Anti-Debug Bypass Snippet

Use Frida to hook and bypass common anti-debugging API checks at runtime:

```javascript
// Frida Script: bypass_antidebug.js
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function (args) {
        console.log("[+] Hooked ptrace! Spoofing return value...");
    },
    onLeave: function (retval) {
        retval.replace(0); // Force return 0 (Success)
    }
});

Interceptor.attach(Module.findExportByName(null, "exit"), {
    onEnter: function (args) {
        console.log("[!] Prevented anti-debug exit(" + args[0] + ")");
        // Prevent process exit by replacing with no-op or returning
    }
});
```

Run command: `frida -l bypass_antidebug.js ./binary`
