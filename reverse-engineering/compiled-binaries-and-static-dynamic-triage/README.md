# Compiled Binaries & Static/Dynamic Triage

### Binary Formats & Header Analysis

Compiled executables organize machine instructions, data sections, and dynamic library linking instructions into standard binary formats.

```
 ┌─────────────────────────────────────────────────────────┐
 │               EXECUTABLE BINARY FORMATS                 │
 └────────────────────────────┬────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ ELF (Linux/Unix)│  │ PE (Windows)    │  │ Mach-O (macOS)  │
│ .text, .data,   │  │ .text, .rdata,  │  │ __TEXT, __DATA, │
│ .bss, .got.plt  │  │ .idata, .edata  │  │ __objc_selrefs  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

***

### Static Analysis Triage Workflow

1. **Format Identification:** Run `file binary` and `readelf -h binary` to identify architecture (x86\_64, ARM64, MIPS), endianness, and entry point address.
2. **Security Protections:** Run `checksec --file=binary` to check PIE (Position Independent Executable), Stack Canaries, NX (No-Execute), and RELRO.
3. **String Disclosure:** Run `strings -a binary | grep -iE "flag|ctf|secret"` to check for hardcoded validation strings or flag fragments.
4. **Symbol & Import Table:** Run `nm -D binary` or `readelf -s binary` to inspect dynamic symbol imports (`strcmp`, `ptrace`, `system`).

***

### Dynamic Analysis with GDB & pwndbg

Dynamic analysis executes the binary under controlled environment monitoring to inspect registers, memory buffers, and control flow transitions.

#### Key GDB Operations

* **Breakpoint Placement:** Use `start` to break at `main()`. Use `breakrva 0x1234` for PIE binaries to break at relative virtual offsets.
* **Register Inspection:** Use `info registers` or `x/s $rdi` to inspect function call arguments passed in System V ABI registers.
* **Memory Dump Strategy:** Set a breakpoint right before the final `strcmp` / `memcmp` check, run with arbitrary input of expected length, and inspect `$rsi` / `$rdi` memory addresses to read the computed flag directly from process memory!
