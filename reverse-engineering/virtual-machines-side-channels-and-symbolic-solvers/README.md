# Virtual Machines, Side-Channels & Symbolic Solvers

### Custom Virtual Machine (VM) Reversing

Custom VM crackmes execute a custom bytecode array inside a virtual interpreter loop.

```
[ Encrypted / Custom Bytecode ]
              │
              ▼
[ Dispatcher Loop (while / switch) ] ──► Decodes Opcode Byte
              │
              ├─► Opcode 0x01: ADD reg1, reg2
              ├─► Opcode 0x02: XOR reg1, key
              └─► Opcode 0x03: CMP reg1, target
```

#### VM Reversing Workflow

1. Identify the VM Context Structure holding Virtual Registers (`VREGS`), Virtual Instruction Pointer (`VIP`), and Virtual Stack Pointer (`VSP`).
2. Reverse opcode handlers in the dispatcher loop.
3. Write a custom Python disassembler to lift VM bytecode into readable assembly instructions!

***

### Instruction Counting & Timing Side-Channels

When a binary compares input character-by-character and exits on the first wrong character:

* Correct characters execute **more CPU instructions**.
* **Execution Oracle:** Measure executed instruction counts using `valgrind --tool=callgrind` to brute-force the flag byte-by-byte!
* **`LD_PRELOAD` Hooking:** Force `strcmp`/`memcmp` hooks to print comparison arguments dynamically.

***

### Symbolic Execution (`angr`) & Constraint Solving (`Z3`)

* **Z3 Theorem Prover:** Model input bytes as symbolic bit-vectors (`BitVec`) and add validation constraints extracted from disassembly to solve math equations automatically.
* **`angr` Framework:** Explores binary execution paths symbolically. Specify `find` (target success address) and `avoid` (error path address) to solve flags without manual reversing.
