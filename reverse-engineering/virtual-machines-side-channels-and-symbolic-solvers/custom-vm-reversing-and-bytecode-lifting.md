# Custom VM Reversing & Bytecode Lifting

Analyzing custom virtual machines (VM crackmes), opcode extraction, dispatcher loops, and solving VM constraints via Z3.

***

### 1. Custom Virtual Machine Architecture

Custom VM challenges embed a custom bytecode interpreter inside the binary.

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

***

### 2. VM Reversing Workflow

#### Step 1: Locate Virtual Registers & Instruction Pointer (VIP)

Find the VM context structure holding:

* `VIP` (Virtual Instruction Pointer)
* `VSP` (Virtual Stack Pointer)
* `VREGS` (Virtual Register Array: `vreg[0]`, `vreg[1]`, ...)

#### Step 2: Map Opcode Handlers

Reverse each case statement in the dispatcher loop:

| Opcode Byte | Handler Assembly           | Disassembled Semantics |
| ----------- | -------------------------- | ---------------------- |
| `0x10`      | `vreg[arg1] += vreg[arg2]` | `ADD vreg1, vreg2`     |
| `0x20`      | `vreg[arg1] ^= arg2`       | `XOR vreg1, imm`       |
| `0x30`      | `vreg[arg1] == target`     | `CMP vreg1, target`    |

***

### 3. Disassembling Custom Bytecode with Python

Write a quick disassembler script in Python to dump the execution trace:

```python
bytecode = bytes.fromhex("10010220014230017f") # Raw VM bytes
vip = 0

while vip < len(bytecode):
    op = bytecode[vip]
    if op == 0x10:
        print(f"{vip:04x}: ADD vreg{bytecode[vip+1]}, vreg{bytecode[vip+2]}")
        vip += 3
    elif op == 0x20:
        print(f"{vip:04x}: XOR vreg{bytecode[vip+1]}, {hex(bytecode[vip+2])}")
        vip += 3
    elif op == 0x30:
        print(f"{vip:04x}: CMP vreg{bytecode[vip+1]}, {hex(bytecode[vip+2])}")
        vip += 3
    else:
        print(f"Unknown opcode {hex(op)} at {vip}")
        break
```
