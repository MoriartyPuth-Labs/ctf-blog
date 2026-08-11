# OLLVM & Compiler Obfuscations

Deobfuscating OLLVM (Obfuscated LLVM) passes: Control Flow Flattening (CFF), Instruction Substitution, Bogus Control Flow (BCF), and automated deobfuscation plugins.

***

### 1. OLLVM Pass Types & Characteristics

OLLVM transforms intermediate representation (IR) during compilation:

| OLLVM Pass                            | Transformation Mechanism                                                                       | Signature Pattern                                    |
| ------------------------------------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| **Control Flow Flattening (`-fla`)**  | Flattens control flow into central `switch-case` dispatcher loop                               | Large `while(1) switch(state)` blocks                |
| **Instruction Substitution (`-sub`)** | Replaces simple operations with complex equivalents (`a = b + c` $\rightarrow$ `a = b - (-c)`) | Abundance of bitwise operations (`AND`, `OR`, `XOR`) |
| **Bogus Control Flow (`-bcf`)**       | Adds fake basic blocks guarded by opaque predicates                                            | Unreachable dead code blocks with complex conditions |

***

### 2. Automated Deobfuscation Frameworks

#### 2.1 D-810 (Ghidra Plugin)

**D-810** is an automated Ghidra plugin that simplifies microcode rules, stripping instruction substitution and opaque predicates during decompilation.

* **Usage:** Install D-810 in Ghidra $\rightarrow$ Open Decompiler $\rightarrow$ Right-click $\rightarrow$ _D-810 Deobfuscate_.

#### 2.2 GOOMBA (OLLVM Control Flow Un-flattener)

GOOMBA uses symbolic execution via `angr` to trace basic block state transitions and patch jump targets directly, eliminating dispatcher loops.

***

### 3. Manual Symbolic De-flattening Script (`angr`)

```python
import angr

# 1. Load Obfuscated Binary
proj = angr.Project('./ollvm_binary', auto_load_libs=False)

# 2. Identify Dispatcher & Basic Blocks
dispatcher_addr = 0x401230
start_block = 0x401200

# 3. Use angr to find execution paths from each basic block to its successor
def get_successor(block_addr):
    state = proj.factory.blank_state(addr=block_addr)
    simgr = proj.factory.simulation_manager(state)
    simgr.step()
    # Step through until leaving dispatcher
    for s in simgr.active:
        if s.addr != dispatcher_addr:
            return s.addr
    return None

print("[+] Resolved Basic Block Connections!")
```
