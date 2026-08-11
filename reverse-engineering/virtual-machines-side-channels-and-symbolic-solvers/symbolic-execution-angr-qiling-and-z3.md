# Symbolic Execution (angr), Qiling, & Z3

Automated constraint solving with Z3, symbolic execution with `angr`, and OS-level emulation using `Qiling`.

***

### 1. Z3 Theorem Prover Cheatsheet

Use Z3 to solve mathematical flag validation constraints automatically:

```python
from z3 import *

# 1. Create 8-bit symbolic vector variables for 16-byte flag
flag = [BitVec(f'flag_{i}', 8) for i in range(16)]
solver = Solver()

# 2. Add Constraints (e.g. ASCII printable range)
for b in flag:
    solver.add(b >= 32, b <= 126)

# 3. Add Validation Equations extracted from binary
solver.add(flag[0] ^ flag[1] == 0x42)
solver.add(flag[2] + flag[3] == 0x90)
solver.add(flag[0] == ord('C'))
solver.add(flag[1] == ord('T'))

# 4. Check Satisfiability & Output Solution
if solver.check() == sat:
    m = solver.model()
    solution = "".join([chr(m[b].as_long()) for b in flag])
    print(f"[+] Solved Flag: {solution}")
else:
    print("[-] Unsatisfiable constraints!")
```

***

### 2. Symbolic Execution with `angr`

`angr` explores binary paths symbolically without manual disassembly.

```python
import angr, claripy

# 1. Load Binary
project = angr.Project('./binary', auto_load_libs=False)

# 2. Create 32-byte Symbolic Input Buffer
flag_chars = [claripy.BVS(f'char_{i}', 8) for i in range(32)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# 3. Initial State Setup
state = project.factory.full_init_state(
    stdin=flag,
    add_options={angr.options.LAZY_SOLVES}
)

# 4. Enforce Printable ASCII Constraints
for c in flag_chars:
    state.solver.add(c >= 32, c <= 126)

# 5. Path Exploration Simulation
simgr = project.factory.simulation_manager(state)
# Target addresses: Find 'Success' (0x401290), Avoid 'Wrong' (0x4012b0)
simgr.explore(find=0x401290, avoid=0x4012b0)

if simgr.found:
    found_state = simgr.found[0]
    print("[+] Solved Flag:", found_state.posix.dumps(0))
else:
    print("[-] Target state not reachable.")
```

***

### 3. Emulation with Qiling Framework

Qiling emulates cross-platform binaries (ARM, MIPS, x86\_64, Windows, Linux, macOS) without foreign hardware:

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

# Emulate ARM64 Linux binary on Windows host
ql = Qiling(["./arm64_binary"], rootfs="./rootfs/arm64_ubuntu", verbose=QL_VERBOSE.OFF)

# Hook specific function address to dump output
def hook_check(ql):
    print("[+] Reached check function!")
    reg_val = ql.arch.regs.x0
    print(f"X0 Register: {hex(reg_val)}")

ql.hook_address(hook_check, 0x1234)
ql.run()
```
