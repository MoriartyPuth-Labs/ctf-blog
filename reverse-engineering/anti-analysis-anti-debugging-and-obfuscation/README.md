# Anti-Analysis, Anti-Debugging & Obfuscation

### Linux & Windows Anti-Debugging Mechanics

Anti-debugging logic checks for process monitoring flags to prevent researchers from analyzing binaries in GDB or x64dbg.

#### Linux Anti-Debug Attacks

* **`ptrace(PTRACE_TRACEME)`:** Binaries execute `ptrace(0, 0, 0, 0)`. If a debugger is attached, `ptrace` fails $\rightarrow$ Binary terminates.
  * _Bypass:_ Hook `ptrace` via `LD_PRELOAD` shared library or GDB syscall catching (`set $rax = 0`).
* **`/proc/self/status` TracerPID:** Reading process status file to check if `TracerPID != 0`.
  * _Bypass:_ Patch string `"TracerPID"` in hex editor to disable string matching.

#### Windows Anti-Debug Attacks

* **PEB Checks:** Reading `BeingDebugged` flag (`PEB + 0x02`) or `NtGlobalFlag`.
* **TLS Callbacks:** Executing anti-debug checks inside Thread Local Storage callbacks **before** the main entry point runs.

***

### Nanomite Architectures & Self-Modifying Code (SMC)

* **Self-Modifying Code (SMC):** Binaries decrypt internal `.text` instructions at runtime using `mprotect()` or `VirtualProtect()`.
  * _Strategy:_ Break _after_ decryption loop, then dump decrypted instructions in memory.
* **Nanomite Debug Loops:** The binary forks into a parent debugger process and a child debuggee process. The child replaces original instructions with `INT3` (`0xCC`). When executed, the parent catches `SIGTRAP` signals, executes the real math, and updates the child's registers.

***

### Deobfuscating OLLVM & Control Flow Flattening (CFF)

Compiler obfuscators (OLLVM) obscure basic blocks by replacing standard `if/for` logic with a central `switch-case` dispatcher loop driven by a state variable.

```
[ Basic Control Flow ]           [ Control Flow Flattening (OLLVM) ]
   Block A ──► Block B                         Switch Dispatcher
      │           │                                   ▲
      ▼           ▼                                   │
   Block C ──► Block D                   ┌────────────┴────────────┐
                                         ▼            ▼            ▼
                                      Case 1       Case 2       Case 3
```

#### De-flattening Strategies

1. **D-810 Ghidra Plugin:** Simplifies microcode rules and strips instruction substitution during decompilation.
2. **GOOMBA & angr:** Uses symbolic execution to trace basic block state transitions and patch jump targets directly to eliminate dispatcher loops.
