# Maze

> **Challenge — "Please try to understand this binary and solve it!"**
>
> _"Welcome to the maze! Please type your input:"_
>
> **File:** `maze` (ELF64, statically linked, stripped pure-assembly binary)

**Solution:** `4444221122221111331133334433443344333344334433113333443333113311111111112211113333331122113311221111113333444444444444442244224433442244443333113344442222444433444422442244442244221111224444221111111122111122442211224444443344222222442244224433334422222244333333444444333311331133331111224422111111224422111133333333442244333333333333113311113311331111334433331122113333331122111111221133331122222244444433444422112211111122112211331133443333333333334422443333331133331122113311221111112222113311334433113333111111221111224444221111111111224422443344444444222244222211221122444444333333443344443333442244224422222222221111333333331122112211224422442244442211111133113311222211111111221111331133334433111122112244222244221122111122113333334422443333111133443333113344334422443344443333111122111111333344224433331133331133334433331133444422222222224444443311113333333344444422111122444444334444334444222244222244333344333344222244222244334444442222442222443333442222224422443333444444333344444422224444334433333311113333334444221122444433334444444422444422224422444444444444442211111111222244334444222222442222222211224422221111333333334433331133331111224422221111221111221122221111112244444444444444442211221133111111222211331133111111113333334433442244`

#### File Verification

|              |                                                       |
| ------------ | ----------------------------------------------------- |
| **Filename** | `maze`                                                |
| **Size**     | `1082368` bytes (\~1057 KB)                           |
| **SHA-256**  | _(download from source — not bundled in this repo)_   |
| **MD5**      | _(download from source — not bundled in this repo)_   |
| **Source**   | https://crackmes.one/crackme/5f009fa233c5d42850709479 |
| **Author**   | [jeffli6789](https://crackmes.one/user/jeffli6789)    |

```bash
# Download from crackmes.one (free account required)
# Unzip the downloaded archive, the binary inside is named 'maze'
chmod +x maze
```

***

### Table of Contents

1. TL;DR
2. Tooling
3. Initial Triage
4. Behavioural Analysis
5. Entry Point — The Only Call That Matters
6. Dissecting the Maze Node
7. Recognising the Structure
8. Finding the Exit
9. Solving with BFS
10. Full Solver (PoC)
11. Reproduction Steps
12. Confirming on the Binary
13. Appendix: Key Addresses

***

### TL;DR

The binary reads an input string and feeds it character by character through a chain of identical 106-byte assembly nodes. Each node reads one digit (`1`–`4`), uses it to compute a signed jump delta, and leaps to the next node in the binary's address space. Dead ends return `0` (`XOR EAX,EAX; RET`). There is exactly **one** node in the entire 1 MB binary that returns `1` — the exit.

|                     | Detail                                                  |
| ------------------- | ------------------------------------------------------- |
| **Technique**       | Address-space maze encoded in raw assembly              |
| **Node size**       | 106 bytes (identical pattern, tiled across the binary)  |
| **Valid moves**     | `1` `2` `3` `4` (map to four signed jump deltas)        |
| **Dead ends**       | `XOR EAX,EAX; RET` scattered throughout                 |
| **Exit node**       | `0x0CB2C8` — `MOV EAX,1; RET`                           |
| **Solution length** | 684 characters                                          |
| **Solve method**    | BFS over the address graph from `0x716D0` to `0x0CB2C8` |

Because the node structure is fully uniform and the jump deltas are fixed constants, modelling the binary as a graph and running BFS gives the shortest valid input in seconds — no patching, no brute force, no crypto.

***

### Tooling

| Tool                                            | Purpose                                                                 |
| ----------------------------------------------- | ----------------------------------------------------------------------- |
| `file`, `ls`, `strings`                         | Initial binary triage                                                   |
| `objdump -d -M intel`                           | Static disassembly — reading the node structure and entry point         |
| `python3`                                       | Exit scanner (`targets.py`) and BFS solver (`solve.py`)                 |
| [`distorm3`](https://github.com/gdabah/distorm) | Python disassembly library used by `targets.py` to locate the exit node |
| `gdb`                                           | Optional — confirming the exit node returns `AL=1` at runtime           |

```bash
pip install distorm3
```

***

### 1. Initial Triage

```console
$ file maze
maze: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped

$ ls -l --block-size=K maze
-rwxrwxr-x 1 root root 1057K Jul 4 17:26 maze

$ strings maze | grep -E 'Well done|Try again|Welcome'
Welcome to the maze!
Please type you input:
Try again!
Well done!
```

Key observations:

* **Statically linked** — no shared libraries, no import table to hint at what the binary does internally. Everything is self-contained.
* **Stripped** — no symbol names, no function boundaries from the linker. Disassembly is raw bytes.
* **1 MB of pure assembly** — far too large for a typical string comparison crackme. This size is the first signal that the binary's structure itself is part of the puzzle.
* **Only four strings matter** — the welcome prompt, the two outcome messages. Nothing else in the string table is useful.

***

### 2. Behavioural Analysis

```console
$ ./maze
Welcome to the maze!
Please type your input:
hello
Try again!

$ ./maze
Welcome to the maze!
Please type your input:
1234
Try again!
```

Wrong input always prints `Try again!`. There is no timing difference, no partial match feedback, no crash. The binary either succeeds or fails atomically — which rules out oracle-based side-channel approaches. We need to understand the logic statically.

***

### 3. Entry Point — The Only Call That Matters

Disassembling from the binary's entry point:

```bash
$ objdump -d -M intel --start-address=0xb0 --stop-address=0x13b maze
```

```asm
; ── print welcome prompt ──────────────────────────────────────────────────────
000000b0: ba 2e 00 00 00       MOV  EDX, 0x2e        ; 46 bytes
000000b5: 48 be 14 81 70 00    MOV  RSI, 0x708114    ; "Welcome to the maze!\nPlease type you input:\n"
000000bf: bf 01 00 00 00       MOV  EDI, 0x1         ; stdout
000000c4: b8 01 00 00 00       MOV  EAX, 0x1         ; syscall: write
000000c9: 0f 05                SYSCALL

; ── read user input ───────────────────────────────────────────────────────────
000000cb: b8 00 00 00 00       MOV  EAX, 0x0         ; syscall: read
000000d0: bf 02 00 00 00       MOV  EDI, 0x2         ; fd=2 (redirected stdin)
000000d5: 48 be 5c 81 70 00    MOV  RSI, 0x70815c    ; input buffer
000000df: ba 10 27 00 00       MOV  EDX, 0x2710      ; max 10000 bytes
000000e4: 0f 05                SYSCALL

; ── THE single function call ──────────────────────────────────────────────────
000000e6: 48 bf 5c 81 70 00    MOV  RDI, 0x70815c    ; pass buffer pointer as arg
000000f0: e8 db 15 07 00       CALL 0x716d0          ; ← must return AL != 0

; ── outcome branch ────────────────────────────────────────────────────────────
000000f5: 84 c0                TEST AL, AL
000000f7: 74 1d                JZ   0x116            ; zero  → "Try again!"
                                                     ; non-zero → "Well done!"
000000f9: ba 0c 00 00 00       MOV  EDX, 0xc
000000fe: 48 be 4e 81 70 00    MOV  RSI, 0x70814e    ; "Well done!\n"
00000108: bf 01 00 00 00       MOV  EDI, 0x1
0000010d: b8 01 00 00 00       MOV  EAX, 0x1
00000112: 0f 05                SYSCALL
00000114: eb 1b                JMP  0x131

00000116: ba 0c 00 00 00       MOV  EDX, 0xc
0000011b: 48 be 42 81 70 00    MOV  RSI, 0x708142    ; "Try again!\n"
00000125: bf 01 00 00 00       MOV  EDI, 0x1
0000012a: b8 01 00 00 00       MOV  EAX, 0x1
0000012f: 0f 05                SYSCALL
```

The entire challenge hinges on `CALL 0x716d0` returning `AL = 1`. Everything else is scaffolding.

***

### 4. Dissecting the Maze Node

Jumping to `0x716d0`, I expected a password check or crypto routine. Instead:

```asm
; ── read one byte from input string ─────────────────────────────────────────
000716d0: 8a 07                MOV  AL, [RDI]           ; read current byte
000716d2: 48 ff c7             INC  RDI                 ; advance input pointer

; ── newline = end of input → return 0 ────────────────────────────────────────
000716d5: 3c 0a                CMP  AL, 0x0a            ; '\n' ?
000716d7: 74 5e                JZ   0x71737             ; yes → dead end

; ── convert ASCII digit to integer ───────────────────────────────────────────
000716d9: 2c 30                SUB  AL, 0x30            ; '1'→1, '2'→2, etc.

; ── digit 1: RBX=-1, RCX=0x65 ────────────────────────────────────────────────
000716db: 3c 01                CMP  AL, 0x1
000716dd: 75 0e                JNZ  0x716ed
000716df: 48 c7 c3 ff ff ff ff MOV  RBX, -0x1
000716e6: b9 65 00 00 00       MOV  ECX, 0x65
000716eb: eb 32                JMP  0x7171f

; ── digit 2: RBX=-1, RCX=0x01 ────────────────────────────────────────────────
000716ed: 3c 02                CMP  AL, 0x2
000716ef: 75 0e                JNZ  0x716ff
000716f1: 48 c7 c3 ff ff ff ff MOV  RBX, -0x1
000716f8: b9 01 00 00 00       MOV  ECX, 0x1
000716fd: eb 20                JMP  0x7171f

; ── digit 3: RBX=+1, RCX=0x01 ────────────────────────────────────────────────
000716ff: 3c 03                CMP  AL, 0x3
00071701: 75 0c                JNZ  0x7170f
00071703: bb 01 00 00 00       MOV  EBX, 0x1
00071708: b9 01 00 00 00       MOV  ECX, 0x1
0007170d: eb 10                JMP  0x7171f

; ── digit 4: RBX=+1, RCX=0x65 ────────────────────────────────────────────────
0007170f: 3c 04                CMP  AL, 0x4
00071711: 75 24                JNZ  0x71737             ; anything else → dead end
00071713: bb 01 00 00 00       MOV  EBX, 0x1
00071718: b9 65 00 00 00       MOV  ECX, 0x65
0007171d: eb 00                JMP  0x7171f

; ── compute jump target ───────────────────────────────────────────────────────
0007171f: 48 0f af d9          IMUL RBX, RCX            ; RBX = RBX * RCX
00071723: 48 6b db 6a          IMUL RBX, RBX, 0x6a      ; RBX = RBX * 106
00071727: 48 8d 05 f9 ff ff ff LEA  RAX, [RIP-0x7]      ; RAX = 0x71727 (self-ref)
0007172e: 48 83 e8 57          SUB  RAX, 0x57           ; RAX = 0x716d0 (node base)
00071732: 48 01 d8             ADD  RAX, RBX            ; RAX = node_base + delta
00071735: ff e0                JMP  RAX                 ; leap to next node

; ── dead end ─────────────────────────────────────────────────────────────────
00071737: 31 c0                XOR  EAX, EAX
00071739: c3                   RET                      ; return 0
```

The delta arithmetic unpacked:

| Digit | RBX | RCX | Calculation    | Delta   |
| ----- | --- | --- | -------------- | ------- |
| `1`   | -1  | 101 | -1 × 101 × 106 | -0x29D2 |
| `2`   | -1  | 1   | -1 × 1 × 106   | -0x006A |
| `3`   | +1  | 1   | 1 × 1 × 106    | +0x006A |
| `4`   | +1  | 101 | 1 × 101 × 106  | +0x29D2 |

Every digit jumps to a new address relative to the current node. Whatever lives at that address executes next — and it is always either the same 106-byte block (another node to traverse) or `31 C0 C3` (dead end, return 0).

***

### 5. Recognising the Structure

The function at `0x716d0` never calls any subroutine. It just jumps. The destination of each jump is a copy of the same 106-byte block elsewhere in the binary — which itself reads the next input byte, computes a delta, and jumps again. This continues until one of two things happens:

* Code at the destination is `XOR EAX,EAX; RET` → dead end, return 0.
* Code at the destination is `MOV EAX,1; RET` → exit, return 1.

The entire 1 MB binary is nothing but the 106-byte node pattern tiled across the address space, with dead ends (`31 C0 C3`) filling the gaps. **The binary's address layout is the maze itself.** Digits `1`–`4` are the four directional moves through it.

***

### 6. Finding the Exit

Somewhere in the binary a single node must return 1 instead of 0. Manually scanning 1 MB of disassembly is not practical, so I wrote `targets.py` to find it programmatically.

The idea: iterate every instruction using `distorm3`, track the previous one. Whenever we see a `RET` (`c3`) that is **not** preceded by `XOR EAX,EAX` (`31 c0`), flag it. Dead ends all follow the `31 c0 c3` sequence — the exit won't.

**`targets.py`:**

```python
import distorm3

filename = "maze"
offset   = 0xb0          # skip the entry stub
length   = distorm3.Decode64Bits

code     = open(filename, "rb").read()[offset:]
prev     = None
iterable = distorm3.DecodeGenerator(offset, code, length)

for (off, size, instruction, hexdump) in iterable:
    # RET not preceded by XOR EAX,EAX  →  candidate exit node
    if hexdump == "c3" and prev is not None and prev[1] != "31c0":
        print("-------------------------------------------")
        print("%.8x: %-32s %s" % prev)
        print("%.8x: %-32s %s" % (off, hexdump, instruction))
        print("-------------------------------------------")
    prev = (off, hexdump, instruction)
```

```console
$ python3 targets.py
-------------------------------------------
000cb2c8: b801000000           MOV EAX, 0x1
000cb2cd: c3                   RET
-------------------------------------------
```

Exactly one hit. `0x0CB2C8` — the only node in the entire binary that returns `AL = 1`. This is the exit.

***

### 7. Solving with BFS

With start, exit, move deltas, and the structure of valid vs dead-end nodes all known, this reduces to a shortest-path problem on a graph where addresses are nodes and the four deltas are edges.

BFS guarantees the shortest solution and naturally produces the move sequence as it runs. The constraints:

* **Valid node:** bytes at address match the 106-byte node pattern exactly
* **Dead end:** bytes at address are `31 C0 C3` — prune this branch
* **Bounds:** only addresses in `[0x13B, 0x1080A8]` can hold valid nodes
* **Visited set:** prevents revisiting nodes, avoids infinite loops

**`solve.py`:**

```python
# Full 106-byte node pattern — identical at every valid node in the binary
pattern = (
    b"\x8A\x07\x48\xFF\xC7\x3C\x0A\x74\x5E\x2C\x30\x3C\x01\x75\x0E"
    b"\x48\xC7\xC3\xFF\xFF\xFF\xFF\xB9\x65\x00\x00\x00\xEB\x32\x3C\x02"
    b"\x75\x0E\x48\xC7\xC3\xFF\xFF\xFF\xFF\xB9\x01\x00\x00\x00\xEB\x20"
    b"\x3C\x03\x75\x0C\xBB\x01\x00\x00\x00\xB9\x01\x00\x00\x00\xEB\x10"
    b"\x3C\x04\x75\x24\xBB\x01\x00\x00\x00\xB9\x65\x00\x00\x00\xEB\x00"
    b"\x48\x0F\xAF\xD9\x48\x6B\xDB\x6A\x48\x8D\x05\xF9\xFF\xFF\xFF\x48"
    b"\x83\xE8\x57\x48\x01\xD8\xFF\xE0\x31\xC0\xC3"
)

dead_end    = b"\x31\xC0\xC3"   # XOR EAX,EAX; RET
start       = 0x0716D0          # entry call target
exit_node   = 0x0CB2C8          # only node that returns 1
lower_bound = 0x00013B
upper_bound = 0x1080A8

moves = [
    (-0x29D2, "1"),
    (-0x006A, "2"),
    ( 0x006A, "3"),
    ( 0x29D2, "4"),
]

maze    = open("maze", "rb").read()
visited = {start}
queue   = [(start, "")]

while queue:
    addr, path = queue.pop(0)

    if addr == exit_node:
        print("[+] Solution found!")
        print("[+] Input length: %d" % len(path))
        print("[+] Input:\n%s" % path)
        break

    if not (lower_bound <= addr <= upper_bound):
        continue

    if maze[addr : addr + len(dead_end)] == dead_end:
        continue

    if maze[addr : addr + len(pattern)] != pattern:
        print("[!] Unexpected code at %s — investigate manually" % hex(addr))
        break

    for delta, move_char in moves:
        next_addr = addr + delta
        if next_addr not in visited:
            visited.add(next_addr)
            queue.append((next_addr, path + move_char))
```

***

### 8. Full Solver (PoC)

```console
$ python3 solve.py
[+] Solution found!
[+] Input length: 684
[+] Input:
4444221122221111331133334433443344333344334433113333443333113311111111112211113333331122113311221111113333444444444444442244224433442244443333113344442222444433444422442244442244221111224444221111111122111122442211224444443344222222442244224433334422222244333333444444333311331133331111224422111111224422111133333333442244333333333333113311113311331111334433331122113333331122111111221133331122222244444433444422112211111122112211331133443333333333334422443333331133331122113311221111112222113311334433113333111111221111224444221111111111224422443344444444222244222211221122444444333333443344443333442244224422222222221111333333331122112211224422442244442211111133113311222211111111221111331133334433111122112244222244221122111122113333334422443333111133443333113344334422443344443333111122111111333344224433331133331133334433331133444422222222224444443311113333333344444422111122444444334444334444222244222244333344333344222244222244334444442222442222443333442222224422443333444444333344444422224444334433333311113333334444221122444433334444444422444422224422444444444444442211111111222244334444222222442222222211224422221111333333334433331133331111224422221111221111221122221111112244444444444444442211221133111111222211331133111111113333334433442244
```

***

### 9. Reproduction Steps

#### Prerequisites

```bash
# Linux x86-64 or WSL2 on Windows
sudo apt-get install -y python3 python3-pip binutils gdb
pip3 install distorm3
```

#### Step 1 — Download the binary

Get the binary from [crackmes.one](https://crackmes.one/crackme/5f009fa233c5d42850709479) (free account required). Unzip the downloaded archive and locate the `maze` binary.

```bash
chmod +x maze
```

#### Step 2 — Confirm baseline behaviour

```console
$ echo "test" | ./maze
Welcome to the maze!
Please type your input:
Try again!
```

#### Step 3 — Find the exit node

Place `targets.py` in the same directory as `maze` and run it:

```console
$ python3 targets.py
-------------------------------------------
000cb2c8: b801000000           MOV EAX, 0x1
000cb2cd: c3                   RET
-------------------------------------------
```

One result. `0x0CB2C8` is the exit.

#### Step 4 — Run the BFS solver

Place `solve.py` in the same directory and run it:

```console
$ python3 solve.py
[+] Solution found!
[+] Input length: 684
[+] Input:
4444...2244
```

#### Step 5 — Feed the solution to the binary

```console
$ echo -n "4444221122221111331133334433443344333344334433113333443333113311111111112211113333331122113311221111113333444444444444442244224433442244443333113344442222444433444422442244442244221111224444221111111122111122442211224444443344222222442244224433334422222244333333444444333311331133331111224422111111224422111133333333442244333333333333113311113311331111334433331122113333331122111111221133331122222244444433444422112211111122112211331133443333333333334422443333331133331122113311221111112222113311334433113333111111221111224444221111111111224422443344444444222244222211221122444444333333443344443333442244224422222222221111333333331122112211224422442244442211111133113311222211111111221111331133334433111122112244222244221122111122113333334422443333111133443333113344334422443344443333111122111111333344224433331133331133334433331133444422222222224444443311113333333344444422111122444444334444334444222244222244333344333344222244222244334444442222442222443333442222224422443333444444333344444422224444334433333311113333334444221122444433334444444422444422224422444444444444442211111111222244334444222222442222222211224422221111333333334433331133331111224422221111221111221122221111112244444444444444442211221133111111222211331133111111113333334433442244" | ./maze
Welcome to the maze!
Please type your input:
Well done!
```

***

### 10. Confirming on the Binary

To verify that `0x0CB2C8` genuinely returns `AL = 1` at runtime, set a breakpoint there in GDB and check the register after stepping over the `MOV`:

```bash
$ gdb ./maze
```

```
(gdb) break *0x0CB2C8
Breakpoint 1 at 0xcb2c8
(gdb) run
Welcome to the maze!
Please type your input:
4444...2244               ← paste solution string
Breakpoint 1, 0x00000000000cb2c8 in ?? ()
(gdb) ni
(gdb) info registers eax
eax   0x1   1             ← AL = 1 confirmed
(gdb) continue
Well done!
```

The `MOV EAX,0x1; RET` at the exit node is reached, `AL` is 1, and the entry point's `TEST AL, AL` falls through to the success branch — printing `Well done!`.

***

### Appendix: Key Addresses

| Address    | Meaning                                                                  |
| ---------- | ------------------------------------------------------------------------ |
| `0x0000B0` | Entry point — prints prompt, reads input, calls `0x716D0`                |
| `0x0000F0` | `CALL 0x716D0` — the single function call in the binary                  |
| `0x0000F5` | `TEST AL, AL` — outcome branch                                           |
| `0x0000F9` | `"Well done!\n"` print path (non-zero branch)                            |
| `0x000116` | `"Try again!\n"` print path (zero branch)                                |
| `0x0716D0` | **Start node** — first maze node, entry call target                      |
| `0x071727` | `LEA RAX, [RIP-0x7]` — RIP-relative self-reference for delta computation |
| `0x071737` | Dead end pattern — `XOR EAX,EAX; RET` (return 0)                         |
| `0x0CB2C8` | **Exit node** — `MOV EAX,0x1; RET` (only return-1 in the binary)         |
| `0x0CB2CD` | `RET` at exit node                                                       |
| `0x00013B` | Lower bound of maze region                                               |
| `0x1080A8` | Upper bound of maze region                                               |

#### Node Jump Deltas

| Digit | RBX | RCX | Delta (hex) | Delta (dec) |
| ----- | --- | --- | ----------- | ----------- |
| `1`   | -1  | 101 | -0x29D2     | -10706      |
| `2`   | -1  | 1   | -0x006A     | -106        |
| `3`   | +1  | 1   | +0x006A     | +106        |
| `4`   | +1  | 101 | +0x29D2     | +10706      |

#### Maze Layout (Simplified)

```
  0x00013B  ┌────────────────────────────────────┐  lower bound
            │  dead end  (31 C0 C3)              │
            │  node      (106-byte pattern)      │
            │  dead end                          │
            │  node                              │
            │  ...                               │
  0x716D0   │  START NODE  ◄── CALL from entry  │
            │  ...                               │
  0xCB2C8   │  EXIT NODE   MOV EAX,1 / RET  ✓  │
            │  ...                               │
  0x1080A8  └────────────────────────────────────┘  upper bound

  Each node:  read digit → compute delta → JMP addr+delta
  Dead end:   XOR EAX,EAX; RET  →  return 0
  Exit node:  MOV EAX,1;   RET  →  return 1  (one in the whole binary)
```

***

_Solved with `objdump`, `distorm3`, and a BFS graph traversal over the binary's address space. No decompiler needed — the node structure reads cleanly from raw disassembly, and the delta math falls out immediately from two `IMUL` instructions._
