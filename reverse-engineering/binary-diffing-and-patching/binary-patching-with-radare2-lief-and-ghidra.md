# Binary Patching with Radare2, LIEF & Ghidra

Patching binary assembly instructions, modifying headers, and injecting dependencies programmatically.

***

### 1. Patching Assembly Bytes with Radare2 (`r2 -w`)

```bash
r2 -w ./binary
s 0x00401234               # Seek to instruction
wx 9090909090              # Write 5 NOP bytes
wa jmp 0x00401290          # Assemble new jump instruction
```

***

### 2. Programmatic Binary Modification with LIEF

```python
import lief

# Parse ELF Binary
binary = lief.parse("./binary")

# Modify Entry Point
binary.header.entrypoint = 0x401100

# Inject Shared Library Dependency
binary.add_library("libhook.so")

# Save Patched File
binary.write("./binary_patched")
```
