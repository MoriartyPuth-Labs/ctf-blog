# WebAssembly (WASM) & Web RE

Decompiling WebAssembly (`.wasm`) binary modules, inspecting WASM imports/exports, and Ghidra WASM plugin reversing.

***

### 1. WASM Toolchain & Decompilation

```bash
# 1. Convert WASM Binary to Text Format (.wat)
wasm2wat target.wasm -o target.wat

# 2. Decompile WASM to C-like Pseudocode using Wasm-Decompile
wasm-decompile target.wasm -o target.c

# 3. Extract Memory Section Data / Strings
rabin2 -z target.wasm
strings target.wasm
```

***

### 2. Browser DevTools WASM Debugging

1. Open Chrome / Firefox DevTools $\rightarrow$ **Sources** tab.
2. Locate `.wasm` module under page assets.
3. Set breakpoints directly on WASM instruction offsets (e.g. `i32.eq`, `i32.xor`).
4. Inspect WASM Linear Memory (`HEAP32`, `HEAP8`) in console.

***

### 3. Ghidra WASM Plugin Reversing

1. Install Ghidra WASM plugin (**ghidra-wasm-plugin**).
2. Load `target.wasm` into Ghidra.
3. Ghidra decompiles WASM stack-machine instructions into clean C pseudocode, reconstructing local function calls and global memory arrays.
