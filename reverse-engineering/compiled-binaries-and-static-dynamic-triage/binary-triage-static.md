# Binary Triage Static

Fast identification of file types, embedded assets, headers, security protections, and tool commands for Ghidra, Radare2, and IDA.

***

### 1. Initial Triage Commands

```bash
# 1. Inspect File Format & Architecture
file binary
readelf -h binary          # ELF headers (entry point, machine arch)
checksec --file=binary     # Security protections (PIE, NX, Canary, RELRO)

# 2. Extract Plaintext Strings & Search Flags
strings -a binary | grep -iE "flag|ctf|secret|pass|key"
rabin2 -z binary | grep -i "flag"
xxd binary | grep -i "flag"

# 3. List Symbol Table & Imports/Exports
nm -D binary               # Dynamic symbols
readelf -s binary          # All ELF symbols
rabin2 -i binary           # Imported functions
rabin2 -E binary           # Exported functions
```

***

### 2. Radare2 (r2) Cheatsheet

```bash
r2 -d ./binary             # Open binary in debug mode
r2 -A ./binary             # Open and run full analysis (aaa)

# Analysis & Listing Commands
aaa                        # Analyze all (functions, calls, symbols)
afl                        # List all functions
pdf @ main                 # Print disassembly of main
pdf @ sym.flag_checker     # Print disassembly of specific function
iz                         # List strings in data sections
iI                         # Binary information & protections

# Navigation & Graph View
s main                     # Seek to main
VV                         # Enter visual graph mode (press 'p' to switch views, 'R' to refresh)
```

***

### 3. Ghidra Headless & GUI Reference

#### Keybindings (Ghidra GUI)

* **`F5`**: Decompile current function into C pseudocode.
* **`L`**: Rename variable/function at cursor.
* **`T`**: Change variable type (e.g. `char[64]`, `uint64_t`).
* **`X`**: Show Cross-References (Xrefs) to current symbol.
* **`Ctrl + Shift + E`**: Disassemble bytes.

#### Ghidra Headless Script Execution

```bash
analyzeHeadless /path/to/project_dir ProjectName -import ./binary -postScript DecompileScript.py
```

***

### 4. Binary Stripping & Symbol Recovery Strategy

If a binary is **stripped** (`file binary` shows `stripped`):

1. Locate `main()` via libc initialization (`__libc_start_main` parameter):
   * First argument passed to `__libc_start_main` in `_start` is the address of `main()`!
2.  In x86\_64 assembly:

    ```asm
    _start:
        xor ebp, ebp
        mov r9, rdx
        pop rsi
        mov rdx, rsp
        and rsp, 0xfffffff0
        push rax
        push rsp
        lea r8, [__libc_csu_fini]
        lea rcx, [__libc_csu_init]
        lea rdi, [main]           ; <- RDI holds main() address!
        call [__libc_start_main@GOT]
    ```
