# Language-Specific Reverse Engineering

### Go & Rust Compiled Binary Reversing

Modern compiled languages (Go, Rust) generate unique memory layouts, mangled symbols, and runtime features that differ from standard C binaries.

#### Go Binary Characteristics

* **Static Linking:** Go packages are statically compiled into huge binaries (> 2MB).
* **Symbol Recovery (`pclntab`):** Use **GoReSym** to parse process line tables and restore function names, types, and source filenames.
* **Go Strings:** Not null-terminated! Represented as 16-byte structs: `[ Pointer (8B) ] + [ Length (8B) ]`.

#### Rust Binary Characteristics

* **Symbol Demangling:** Rust symbols use `v0` mangling (`_$s...`). Use `rustfilt` to demangle into human-readable module paths.
* **Option & Result Enums:** Look for integer tags (`0` = `Ok`/`Some`, `1` = `Err`/`None`) preceding data fields.

***

### C++ Vtables & RTTI Reconstruction

C++ binaries use virtual function tables (`vtables`) for polymorphism:

* Every object containing `virtual` methods has a `vptr` at offset `0x00` pointing to an array of virtual function pointers in `.rodata`.
* **Strategy:** Locate `vptr` initialization in constructor functions (`this->vptr = &vtable`) and reconstruct class structures in Ghidra/IDA.

***

### Managed Bytecode Reversing (Python & .NET)

* **Python (`.pyc`):** Python bytecode can be decompiled back to readable Python source using `pycdc` or `uncompyle6`.
* **.NET / C# (`.exe`/`.dll`):** .NET binaries compile to Intermediate Language (IL) metadata. Use **dnSpy** or **ILSpy** for dynamic debugging and full C# decompilation.
