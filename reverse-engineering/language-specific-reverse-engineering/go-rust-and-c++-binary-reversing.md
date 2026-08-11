# Go, Rust, & C++ Binary Reversing

Reversing compiled binaries from Go, Rust, and C++. Restoring stripped symbols, RTTI structures, vtables, and standard library patterns.

***

### 1. Go Binary Reversing

Go binaries static-link runtime libraries and mangle/strip standard symbol lookup tables.

#### Key Tools & Commands

*   **GoReSym:** Extracts Go symbol tables, type structures, interfaces, and source code filenames from stripped Go binaries.

    ```bash
    GoReSym -t ./go_binary > symbols.json
    ```
* **Ghidra Script (`go_parse.py`):** Loads `pclntab` (process line table) to restore original function names.

#### Go Specific Idioms

* **Function Returns:** Go functions return multiple values directly on the stack or via multiple registers (Go 1.17+ ABI uses `AX`, `BX`, `CX`, `DI`, `SI`, `R8`, `R9`, `R10`, `R11`).
* **Strings:** Go strings are NOT null-terminated! A Go string is a 16-byte structure: `[ Pointer Address (8 bytes) ] + [ String Length (8 bytes) ]`

***

### 2. Rust Binary Reversing

Rust binaries use LLVM codegen and mangled symbol schemes (`v0` mangling scheme).

#### Symbol Demangling

```bash
# Rust symbol demangler command line
rustfilt "_RNvCs1234_4main4main"
# Output: main::main
```

#### Rust Specific Patterns

1. **Option & Result Enums:** Rust returns `Option<T>` (`Some`/`None`) and `Result<T, E>` (`Ok`/`Err`). Look for discriminant integer tags (e.g. `0` = `Ok`, `1` = `Err`) preceding data fields.
2. **Panic Strings:** Search for `src/` strings or `.rs` file paths to quickly pinpoint critical validation functions!

***

### 3. C++ Reversing (Vtables & RTTI)

#### Virtual Function Tables (Vtables)

In C++, classes with `virtual` methods contain a hidden `vptr` at offset `0x00` pointing to a table of function pointers.

```
[ C++ Object ]               [ Vtable Array in .rodata ]
+-------------------+        +---------------------------+
| vptr (8 bytes)    | ─────► | Address of VirtualFunc1() |
+-------------------+        +---------------------------+
| member_var_1      |        | Address of VirtualFunc2() |
+-------------------+        +---------------------------+
```

#### Restoring Classes in Ghidra / Binary Ninja

1. Identify `vtable` assignment inside Class Constructor functions (`this->vptr = &Vtable_Address`).
2. Use Ghidra's Class Structure Editor to define virtual functions and `this` pointers automatically.
