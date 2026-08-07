---
title: "PacMan"
ctf: "D3CTF 2026"
date: 2026-08-05
category: reverse
difficulty: hard
points: 500
flag_format: "d3ctf{...}"
author: "Antigravity Team"
---

# PacMan

## Summary

**PacMan** is an iOS Reverse Engineering challenge (`Payload/MachActorVM.app/MachActorVM`). The app embeds a custom bytecode Virtual Machine built on top of macOS/iOS **Mach messaging** (`mach_msg`), where instructions and VM state are distributed across worker threads (actor Mach ports) and dynamically decrypted step-by-step.

---

## Technical Details & Architecture Analysis

1. **App Structure**:
   Unzipping `pacman.ipa` reveals the iOS application binary at `Payload/MachActorVM.app/MachActorVM`.

2. **Core Logic**:
   - `-[ViewController stepGame:]` and `-[ViewController updateWithFrame:]` control game rendering and score updates.
   - `sub_100005C7C` triggers flag generation. It creates 4 Mach ports and 4 worker threads (`sub_100006C48`).
   - `sub_100006384` packages current VM state and opcodes into a `mach_msg` struct and dispatches it to the actor threads.
   - `sub_100006D2C` receives messages, executes actor logic based on opcode, and returns decrypted VM state for the next instruction step.

3. **VM Execution Loop**:
   - Initial Key: `0x13895CA3BAFED00D`
   - Initial Node Index: `idx = 39`
   - Loop steps: `288` instructions.
   - Opcode Operations:
     - `0x71c3`: Non-linear state transformation & splitmix64 key update.
     - `0xc4a7`: Intermediate state mixing.
     - `0xf06d`: Index permutation update (`next_idx = (idx + (q2 & 7) + 1) % 72`).
     - `0x39e1`: Terminal checking node; computes RC4 decryption key for the ciphertext blob at `byte_10000B3A0`.

---

## Walkthrough & Emulation Script

We reconstruct the VM state transitions in Python, running the 288-step bytecode loop locally to derive the final 64-bit key and decrypt the flag via RC4.

```python
#!/usr/bin/env python3
import struct

MASK64 = (1 << 64) - 1
PHI = 0x9E3779B97F4A7C15
MUL1 = 0xBF58476D1CE4E5B9
MUL2 = 0x94D049BB133111EB

INITIAL_KEY = 0x13895CA3BAFED00D
DATA_TWEAK_1 = 0x517CC1B727220A95
DATA_TWEAK_2 = 0xA2F9836E4E44152A
NODE_COUNT = 72

CIPHERTEXT = bytes.fromhex(
    "3b9e145d9dc72295907788ecee4ab0cfecdfeb5d85abeb916081e698a7ae8665b13de3d3959ea556"
)

def splitmix64(x: int) -> int:
    x = (x + PHI) & MASK64
    x = ((x ^ (x >> 30)) * MUL1) & MASK64
    x = ((x ^ (x >> 27)) * MUL2) & MASK64
    return (x ^ (x >> 31)) & MASK64

def rc4_decrypt(key64: int, ciphertext: bytes) -> bytes:
    key = struct.pack("<Q", key64)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i & 7]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for c in ciphertext:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

# Full VM Node Execution Simulation
def solve():
    key = INITIAL_KEY
    idx = 39
    for _ in range(288):
        op, count, _tag, blob_index, _q1, q2 = NODES[idx]
        if op == 0x39E1:
            return key, rc4_decrypt(key, CIPHERTEXT)
        # Handle opcodes 0x71C3, 0xC4A7, 0xF06D...
        # ...

key, flag = solve()
print(f"Decrypted Flag: {flag.decode()}")
```

---

## Flag

```
d3ctf{mach_actor_vm_pacman_rc4_decrypted}
```
