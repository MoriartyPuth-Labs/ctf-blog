# Self-Modifying Code (SMC), Nanomites, & Loaders

Advanced binary execution patterns: Self-Modifying Code (SMC), Nanomite architectures (parent-child ptrace debug loops), multi-stage memory unpacking, and Process Hollowing.

***

### 1. Self-Modifying Code (SMC)

Self-Modifying Code alters its own instruction bytes in memory before or during execution.

#### Key Indicators

1. Call to `mprotect(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC)` on Linux, or `VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, ...)` on Windows.
2. XOR/AES decryption loops targeting internal `.text` memory blocks.

#### Reversing SMC in GDB / Ghidra

*   **In GDB:** Set breakpoint _after_ the decryption loop, then dump modified memory:

    ```bash
    (gdb) b *decrypt_loop_end
    (gdb) continue
    (gdb) disass $rip, +100     # Inspect decrypted instructions
    ```
* **In Ghidra:** Use Ghidra Script or memory patching to overwrite encrypted bytes with decrypted bytes, then press **`D`** to re-disassemble.

***

### 2. Nanomites (Parent-Child Debug Loop Architecture)

Nanomites are a protection technique where the binary forks into a **Parent Process (Debugger)** and a **Child Process (Debuggee)**.

```
[ Parent Process (Debugger) ] ──(ptrace / DebugActiveProcess)──► [ Child Process (Debuggee) ]
         ▲                                                                 │
         │ (Catches SIGTRAP / INT3)                                         ▼
         └──────────────────────── Executes Opcode ───────────────── Intentionally Replaces 
                                   Handler Math                     Opcodes with INT3 (0xCC)
```

#### Mechanics

1. The child binary replaces original instruction bytes (e.g. `jmp`, `add`, `xor`) with `INT3` (`0xCC`) or `SIGILL` instructions.
2. When the child executes an `INT3`, it crashes and signals the parent.
3. The parent catches the signal, inspects the child's registers (`PTRACE_GETREGS`), performs the real calculation in parent memory, updates the child's registers (`PTRACE_SETREGS`), and advances the child's `RIP`.

#### Bypass Strategy

1. Trace parent-child IPC channels or `ptrace` signal handlers.
2. Extract the parent's opcode lookup table (maps child `INT3` addresses to intended instructions).
3. Write a Python script (`pwntools` / `LIEF`) to patch the child binary's `0xCC` bytes with original instructions!

***

### 3. Process Hollowing & Multi-Stage Loaders

Process Hollowing creates a legitimate suspended process, unmaps its memory, and injects a malicious payload.

#### API Sequence (Windows)

1. `CreateProcessA(..., CREATE_SUSPENDED)`
2. `NtUnmapViewOfSection(...)` (Unmaps target memory)
3. `VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)`
4. `WriteProcessMemory(...)` (Writes payload PE binary)
5. `SetThreadContext(...)` (Updates `EAX`/`RCX` to payload entry point)
6. `ResumeThread(...)`

#### Reversing Strategy

Set breakpoint on `WriteProcessMemory` or `VirtualProtectEx`, inspect the buffer argument, and dump the unpacked PE payload to disk before `ResumeThread` executes!
