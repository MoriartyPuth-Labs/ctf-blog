# Binary Diffing & Patching

1-Day security patch analysis (BinDiff, Diaphora) and binary modifying/patching using LIEF, Binary Ninja, Ghidra, and radare2.

***

### 1. Binary Diffing (BinDiff & Diaphora)

Binary Diffing compares an unpatched binary (vulnerable) with a patched binary (fixed) to pinpoint security vulnerability fixes (1-Day Analysis).

#### Workflow

1. Export disassembly databases of both binaries from Ghidra/IDA.
2. Run **Diaphora** (IDA/Ghidra diffing plugin) or **BinDiff**.
3. Sort results by **Unmatched Functions** or **Modified Basic Blocks**.
4. Inspect modified conditional checks to isolate the exact vulnerability patch!

***

### 2. Binary Patching Techniques

#### 2.1 Patching Binaries with Radare2 (`r2 -w`)

```bash
# Open binary in write mode
r2 -w ./binary

# Seek to target instruction address
s 0x00401234

# Patch instruction to NOPs (0x90)
wx 9090909090

# Or assemble new instructions directly:
"wa jmp 0x00401290"
```

#### 2.2 Patching Binaries with Python `LIEF`

LIEF allows modifying ELF/PE/Mach-O sections, dynamic imports, and headers programmatically:

```python
import lief

# Load ELF Binary
binary = lief.parse("./binary")

# Add a new imported library dependency (e.g. hook.so)
binary.add_library("hook.so")

# Modify Section Permissions (Make .text RWX)
text_section = binary.get_section(".text")
text_section.flags = lief.ELF.SECTION_FLAGS.WRITE | lief.ELF.SECTION_FLAGS.EXECINSTR

# Save Patched Binary
binary.write("./binary_patched")
print("[+] Successfully patched binary with LIEF!")
```
