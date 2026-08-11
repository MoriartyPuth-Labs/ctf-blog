# Obfuscation & Deobfuscation Techniques

Deobfuscating opaque predicates, Mixed Boolean-Arithmetic (MBA) expressions, Control Flow Flattening (CFF), and IDAPython/Ghidra automated patching scripts.

***

### 1. Control Flow Flattening (CFF)

Control Flow Flattening removes standard `if/else` and `for/while` control loops, replacing them with a central **switch-case dispatcher loop** driven by a state variable.

```
[ Basic Control Flow ]           [ Control Flow Flattening (OLLVM) ]
   Block A ──► Block B                         Switch Dispatcher
      │           │                                   ▲
      ▼           ▼                                   │
   Block C ──► Block D                   ┌────────────┴────────────┐
                                         ▼            ▼            ▼
                                      Case 1       Case 2       Case 3
```

#### Deobfuscation Strategies

1. **Symbolic Execution (angr):** Use `angr` to explore execution paths from entry to exit without unrolling the dispatcher loop manually.
2. **D-810 / GOOMBA Ghidra Plugins:** Automated Ghidra optimization plugins to reconstruct flattened control flow graphs.
3. **Basic Block Patching:** Identify the state variable update in each block and patch the jump instruction to target the next block directly, bypassing the dispatcher loop.

***

### 2. Opaque Predicates

An **Opaque Predicate** is a conditional expression whose outcome is statically known to the author at compile time, but disguised to confuse decompilers (e.g. `if ((x * x + x) % 2 == 0)` is ALWAYS true for all integers $x$).

#### Patching Opaque Predicates (NOPing Dead Branches)

Use IDAPython or Ghidra Python scripts to replace conditional jump instructions (`jz`, `jnz`) with unconditional jumps (`jmp`) or `NOP` bytes (`0x90`).

```python
# Ghidra Python Script: Patch bytes with NOPs (0x90)
start_addr = currentAddress
length = 5
for i in range(length):
    setByte(start_addr.add(i), 0x90)
print("Patched 5 bytes with NOP!")
```

***

### 3. Mixed Boolean-Arithmetic (MBA) Simplification

MBA expressions mix bitwise operations (`AND`, `OR`, `XOR`, `NOT`) with arithmetic operations (`+`, `-`, `*`):

$$\text{Obfuscated: } (x \oplus y) + 2 \cdot (x \land y) \quad \Longrightarrow \quad \text{Simplified: } x + y$$

#### Tools for MBA Simplification

* **Z3 Theorem Prover:** Model the inputs and simplify bit-vector formulas.
* **Arybo / sToke:** Automated MBA simplification libraries.
