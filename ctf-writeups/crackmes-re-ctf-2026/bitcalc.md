# BitCalc

> **Challenge — "Find the correct integer input."**
>
> _"A binary that reads one integer, uses every bit of it to rewrite itself, then calls the code it just built."_

**Valid inputs (any one of these passes):**

```
374274518
-1666634662
-1923834644
1804139300
```

#### File Verification

|                |                                               |
| -------------- | --------------------------------------------- |
| **Filename**   | `main`                                        |
| **Format**     | ELF 64-bit LSB, dynamically linked, stripped  |
| **Source**     | crackmes.one (exact URL unknown from writeup) |
| **Input type** | Signed 32-bit integer via `scanf("%d")`       |

> The binary must be downloaded from crackmes.one. It is not bundled in this repository.

***

### Table of Contents

1. TL;DR
2. Tooling
3. Initial Triage
4. Behavioural Analysis
5. The Input — scanf and Format String
6. The Loop — Bit-by-Bit Self-Modification
7. The Generated Code — Add/Sub Chain
8. The Key Insight — Instruction Encoding
9. Extracting the Operands with GDB
10. The Solver — Recursive Bit Search
11. Full Solver (PoC)
12. Reproduction Steps
13. Confirming on the Binary
14. Appendix: Key Addresses & Constants

***

### TL;DR

The binary reads a signed 32-bit integer, then walks a 160-byte memory region in 5-byte steps (32 iterations). On each iteration it checks the current LSB of the input, shifts the input right by one, and writes either `0x05` or `0x2d` into that memory slot — the opcodes for `add $imm32,%eax` and `sub $imm32,%eax`. After all 32 bits are consumed, it **calls that memory region** as a function. The generated code runs 32 add/sub operations on a starting value in EAX, then compares the final result to a hardcoded target. If they match, the crackme passes.

|                            | Detail                                                                |
| -------------------------- | --------------------------------------------------------------------- |
| **Mechanism**              | Self-modifying code — input bits flip between `add` and `sub` opcodes |
| **Iterations**             | 32 (one per bit of the 32-bit input)                                  |
| **Generated instructions** | 32 × `add/sub $imm32,%eax`, each 5 bytes                              |
| **Starting EAX**           | `0x3df2f794`                                                          |
| **Target EAX**             | `0x7a612770`                                                          |
| **Operands**               | 32 hardcoded 32-bit constants embedded in memory                      |
| **Solve method**           | Recursive DFS over all 2³² bit patterns — terminates in seconds       |
| **Valid solutions**        | 374274518, -1666634662, -1923834644, 1804139300                       |

***

### Tooling

| Tool                              | Purpose                                                                                    |
| --------------------------------- | ------------------------------------------------------------------------------------------ |
| `objdump -d -M intel`             | Static disassembly — reading the input and loop structure                                  |
| `gdb`                             | Dynamic analysis — observing the self-generated code at runtime, extracting operand values |
| Custom GDB script (`extract.gdb`) | Dumps the 32 operand constants from the generated code region                              |
| C solver (`solve.c`)              | Recursive search over all 2³² input combinations to find valid integers                    |

***

### 1. Initial Triage

```console
$ file main
main: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
      dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped

$ strings main | grep -E '%d|correct|wrong|done|again'
%d
Well done!
Try again!
```

Key observations:

* **Dynamically linked** — uses libc. `scanf` and `puts` are the only external functions we care about.
* **Stripped** — no symbols, but the binary is small enough that the disassembly is easy to follow.
* **`%d` format string** — the binary reads exactly one integer. No strings, no buffer, just a number.
* **No crypto imports** — no `openssl`, no `SHA`, nothing. Whatever check is happening is built from scratch.

***

### 2. Behavioural Analysis

```console
$ echo "0" | ./main
Try again!

$ echo "1234567" | ./main
Try again!

$ echo "hello" | ./main
Try again!

$ echo "374274518" | ./main
Well done!
```

The binary accepts exactly one integer and immediately gives a pass/fail verdict. No timing oracle, no partial feedback. The check is binary — either we hit the right value or we don't.

***

### 3. The Input — scanf and Format String

The first interesting thing in the disassembly is the format string load and the `scanf` call:

```asm
; ── load "%d" format string ───────────────────────────────────────────────────
0x6b4:   48 8d 3d 69 02 00 00   lea    0x269(%rip),%rdi      ; "%d"

; ── ... (setup for scanf: stack buffer for the int) ... ──────────────────────

; ── call scanf ────────────────────────────────────────────────────────────────
0x6d8:   e8 a3 ff ff ff         callq  680 <__isoc99_scanf@plt>
```

The binary reads a single signed decimal integer from stdin into a local variable. That integer becomes the key that controls everything that follows.

***

### 4. The Loop — Bit-by-Bit Self-Modification

Right after `scanf` returns, execution enters a loop that runs exactly **32 times** — once per bit of the 32-bit input:

```asm
; ── loop entry ────────────────────────────────────────────────────────────────
0x6ef:   eb 13                  jmp    0x704              ; jump to loop head

; ── bit == 1 path: write add opcode (0x05) ───────────────────────────────────
0x6f1:   0f 1f 80 00 00 00 00   nopl   0x0(%rax)          ; alignment padding
0x6f8:   c6 00 05               movb   $0x5,(%rax)        ; *ptr = 0x05  (add opcode)
0x6fb:   48 83 c0 05            add    $0x5,%rax           ; ptr += 5
0x6ff:   48 39 c6               cmp    %rax,%rsi           ; ptr >= end?
0x702:   74 17                  je     0x71b               ; yes → exit loop

; ── loop head: consume next bit of input ─────────────────────────────────────
0x704:   89 d1                  mov    %edx,%ecx           ; ecx = current input (save copy)
0x706:   d1 fa                  sar    %edx                ; edx >>= 1  (arithmetic right shift)
0x708:   83 e1 01               and    $0x1,%ecx           ; ecx &= 1   (isolate current LSB)
0x70b:   85 c9                  test   %ecx,%ecx           ; bit == 0?
0x70d:   75 e9                  jne    0x6f8               ; bit == 1 → write 0x05 (add)

; ── bit == 0 path: write sub opcode (0x2d) ───────────────────────────────────
0x70f:   c6 00 2d               movb   $0x2d,(%rax)        ; *ptr = 0x2d  (sub opcode)
0x712:   48 83 c0 05            add    $0x5,%rax            ; ptr += 5
0x716:   48 39 c6               cmp    %rax,%rsi            ; ptr >= end?
0x719:   75 e9                  jne    0x704               ; no → continue loop

; ── loop exit ─────────────────────────────────────────────────────────────────
0x71b:   ...
```

**Register assignments:**

| Register | Role                                                                                  |
| -------- | ------------------------------------------------------------------------------------- |
| `%rax`   | Write pointer into the 160-byte code region; incremented by 5 each iteration          |
| `%rsi`   | End pointer of the code region (`rax` start + 160); loop terminates when `rax >= rsi` |
| `%edx`   | Current working copy of user input; right-shifted once per iteration                  |
| `%ecx`   | Temporary holding the current LSB of `%edx` before the shift                          |

Rewritten in C:

```c
char* ptr = code_region;
char* end = code_region + 160;   // exactly 32 iterations (160 / 5 = 32)
int   input = user_input;

while (ptr < end) {
    int bit = input & 1;          // take LSB
    input >>= 1;                  // shift right for next iteration
    if (bit == 1)
        *ptr = 0x05;              // add $imm32, %eax
    else
        *ptr = 0x2d;              // sub $imm32, %eax
    ptr += 5;
}
```

Each bit of the input — starting from the **least significant bit** — writes either an `add` opcode (`0x05`) or a `sub` opcode (`0x2d`) into the code region, spaced 5 bytes apart. The remaining 4 bytes of each slot already hold a 32-bit immediate constant, pre-baked into the binary at load time.

***

### 5. The Generated Code — Add/Sub Chain

After the loop, the binary calls directly into the region it just wrote:

```asm
0x742:   e8 d9 08 20 00         callq  0x201020      ; call self-modified code region
```

Setting a breakpoint at `0x201020` in GDB and examining the memory **after** the loop runs reveals the generated code:

```asm
0x555555755020:   mov  $0x3df2f794,%eax      ; EAX = starting value
0x555555755025:   sub  $0x52ae22f2,%eax      ; (or add — depends on bit 0 of input)
0x55555575502a:   add  $0xbf409bcc,%eax
0x55555575502f:   add  $0x46417dc1,%eax
0x555555755034:   add  $0x25f7d9a1,%eax
0x555555755039:   sub  $0xef83a7ce,%eax
  ...                                        ; 26 more add/sub operations
0x5555557550c0:   sub  $0x4043cd91,%eax
0x5555557550c5:   cmp  $0x7a612770,%eax      ; compare final EAX with target
0x5555557550ca:   sete %al                   ; AL = 1 if equal, 0 otherwise
0x5555557550cd:   nop
0x5555557550ce:   nop
0x5555557550cf:   retq                       ; return AL to caller
```

The generated function:

1. Loads `0x3df2f794` into EAX as the starting value.
2. Runs 32 add/sub operations using the 32 pre-baked immediates, in the order determined by our input's bits.
3. Compares the result to `0x7a612770`.
4. Returns `AL = 1` if they match (`sete`), `0` otherwise.

The opcode/immediate layout in memory (`[opcode] [imm32 little-endian]`):

```
Offset 0:  05/2d  f2 22 ae 52    →  add/sub $0x52ae22f2, %eax
Offset 5:  05/2d  cc 9b 40 bf    →  add/sub $0xbf409bcc, %eax
Offset 10: 05/2d  c1 7d 41 46    →  add/sub $0x46417dc1, %eax
...
```

The **only thing** our input controls is which opcode byte (`05` or `2d`) sits at each 5-byte slot. The immediates are fixed.

***

### 6. The Key Insight — Instruction Encoding

The trick that makes this work is that x86 encodes `add imm32, %eax` and `sub imm32, %eax` as single-byte opcodes followed by a 32-bit immediate:

| Operation          | Opcode | Encoding         |
| ------------------ | ------ | ---------------- |
| `add $imm32, %eax` | `0x05` | `05 xx xx xx xx` |
| `sub $imm32, %eax` | `0x2d` | `2d xx xx xx xx` |

Since the loop writes only the **first byte** of each 5-byte slot, and the following 4 bytes (the immediate) are already in place, flipping one byte between `0x05` and `0x2d` is enough to switch any operation from `add` to `sub` or vice versa.

The binary pre-populates the immediate values at load time. Our input just selects which arithmetic operation each slot performs.

***

### 7. Extracting the Operands with GDB

Before solving, we need the 32 immediate constants. They live in memory at the code region, 1 byte after each 5-byte boundary (at offset +1 of each slot). A short GDB script dumps them all:

**`extract.gdb`:**

```gdb
define display5
  set $cur  = $arg0 + 1     # skip the opcode byte, land on the 4-byte immediate
  set $stop = $arg1
  while $cur < $stop
    print /x *(int *) $cur
    set $cur = $cur + 5
  end
end

# Usage (run after hitting a breakpoint at 0x201020):
# display5 0x555555755020 0x5555557550c5
```

Running this against a live session (with any input so the loop populates the opcode bytes) produces the 32 constants:

```
0x52ae22f2  0xbf409bcc  0x46417dc1  0x25f7d9a1
0xef83a7ce  0x2dd63e8e  0x584a1ec5  0x8e58e1df
0xf2705f70  0x2e94ef1e  0x3ca9e080  0xa617b5df
0x29ae9c3d  0x7461ed52  0x7125faac  0x65dfffd6
0x97f1f41c  0x6f4e0648  0xd803e5d0  0xf358f0eb
0xbc3b30c7  0x585685f8  0x2a9cc47c  0x7f03d175
0xc1d942ae  0x174c7d4f  0xb7d004f0  0xbec8b077
0x8ce8eaa2  0x2510e330  0x4aed0eee  0x4043cd91
```

***

### 8. The Solver — Recursive Bit Search

With the 32 constants and the target in hand, the problem is a **subset-sign search**: choose `+` or `−` for each of the 32 values such that:

```
0x3df2f794  ±  values[0]  ±  values[1]  ±  ...  ±  values[31]  ==  0x7a612770
```

There are 2³² ≈ 4 billion possible sign assignments — too many to enumerate in a tight inner loop. A straightforward recursive DFS tries both branches at each level and stops early when a match is found. Modern CPUs can evaluate all 4 billion paths in a few seconds since each node is just one 32-bit add/subtract and a branch.

One subtlety: the loop consumes bits **LSB-first** (bit 0 of input → first operation), but the recursion builds a `marker` bit pattern **MSB-first** (deepest level = LSB of marker). A bit-reversal step converts the marker back to the correct integer to feed to `scanf`.

**`solve.c`:**

```c
#include <stdio.h>
#include <stdint.h>

/* Starting EAX value (first instruction in the generated code) */
int start = 0x3df2f794;

/* 32 immediate constants (extracted from the binary with extract.gdb) */
int values[32] = {
    0x52ae22f2, 0xbf409bcc, 0x46417dc1, 0x25f7d9a1,
    0xef83a7ce, 0x2dd63e8e, 0x584a1ec5, 0x8e58e1df,
    0xf2705f70, 0x2e94ef1e, 0x3ca9e080, 0xa617b5df,
    0x29ae9c3d, 0x7461ed52, 0x7125faac, 0x65dfffd6,
    0x97f1f41c, 0x6f4e0648, 0xd803e5d0, 0xf358f0eb,
    0xbc3b30c7, 0x585685f8, 0x2a9cc47c, 0x7f03d175,
    0xc1d942ae, 0x174c7d4f, 0xb7d004f0, 0xbec8b077,
    0x8ce8eaa2, 0x2510e330, 0x4aed0eee, 0x4043cd91
};

/* Target value — what EAX must equal after the 32 operations */
int result = 0x7a612770;

/*
 * Reverse all 32 bits of x.
 * Needed because the recursion accumulates bits MSB-first, but
 * the binary reads input LSB-first (SAR shifts LSB out first).
 */
static uint32_t bitrev(uint32_t x) {
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) {
        r |= ((x >> i) & 1) << (31 - i);
    }
    return r;
}

/*
 * Recursive DFS.
 *   level  : which of the 32 values we're deciding +/- for (0-indexed)
 *   sum    : running EAX value so far
 *   marker : bit pattern of choices so far (1=add, 0=sub), accumulated MSB-first
 */
void search(unsigned level, int sum, uint32_t marker) {
    if (level == 31) {
        /* Base case: try both signs for the last value */
        if (sum + values[level] == result)
            printf("%d\n", (int)bitrev((marker << 1) | 1));   /* last bit = 1 (add) */
        if (sum - values[level] == result)
            printf("%d\n", (int)bitrev( marker << 1));         /* last bit = 0 (sub) */
        return;
    }
    /* Recursive case: branch on add (+1) and sub (+0) */
    search(level + 1, sum + values[level], (marker << 1) | 1);
    search(level + 1, sum - values[level],  marker << 1);
}

int main(void) {
    search(0, start, 0);
    return 0;
}
```

***

### 9. Full Solver (PoC)

```console
$ gcc -O2 -o solve solve.c

$ ./solve
374274518
-1666634662
-1923834644
1804139300
```

Four valid inputs. Feed any one of them to the binary:

```console
$ echo "374274518" | ./main
Well done!

$ echo "-1666634662" | ./main
Well done!

$ echo "1804139300" | ./main
Well done!
```

***

### 10. Reproduction Steps

#### Prerequisites

```bash
# Linux x86-64 or WSL2 on Windows
sudo apt-get install -y gcc gdb binutils
```

#### Step 1 — Get the binary

Download from crackmes.one, extract, and make executable:

```bash
chmod +x main
```

#### Step 2 — Confirm baseline behaviour

```console
$ echo "0" | ./main
Try again!
```

#### Step 3 — Identify the code region address

Run the binary in GDB, break just before the `callq` into the generated code, and note the target address:

```bash
$ gdb ./main
(gdb) disassemble
# find the "callq" near 0x742 — note the destination address (e.g. 0x555555755020)
```

#### Step 4 — Extract the 32 operands

Load `extract.gdb`, set a breakpoint at the generated code entry, run with any integer input, then call `display5`:

```bash
(gdb) source extract.gdb
(gdb) break *0x555555755020
(gdb) run <<< "0"
(gdb) display5 0x555555755020 0x5555557550c5
# copy the 32 printed hex values into solve.c
```

#### Step 5 — Compile and run the solver

```console
$ gcc -O2 -o solve solve.c
$ ./solve
374274518
-1666634662
-1923834644
1804139300
```

#### Step 6 — Verify

```console
$ echo "374274518" | ./main
Well done!
```

***

### 11. Confirming on the Binary

To watch the self-modification happen and verify the generated code live:

```bash
$ gdb ./main
```

```
(gdb) break *0x742            # break just before the callq into generated code
(gdb) run <<< "374274518"

Breakpoint 1, 0x0000000000000742 in ?? ()

(gdb) x/33i 0x555555755020   # disassemble the 33 generated instructions
0x555555755020:  mov  $0x3df2f794,%eax
0x555555755025:  sub  $0x52ae22f2,%eax   ← bit 0 of 374274518 = 0 → sub
0x55555575502a:  add  $0xbf409bcc,%eax   ← bit 1 = 1 → add
0x55555575502f:  sub  $0x46417dc1,%eax   ← bit 2 = 0 → sub
  ...
0x5555557550c5:  cmp  $0x7a612770,%eax
0x5555557550ca:  sete %al
0x5555557550cf:  retq

(gdb) continue
Well done!
```

The generated add/sub chain evaluates to exactly `0x7a612770` → `sete` sets `AL = 1` → caller prints `Well done!`.

***

### Appendix: Key Addresses & Constants

#### Key Addresses

| Address    | Meaning                                                            |
| ---------- | ------------------------------------------------------------------ |
| `0x6b4`    | `lea 0x269(%rip),%rdi` — load `"%d"` format string for scanf       |
| `0x6d8`    | `callq __isoc99_scanf@plt` — read user integer into stack variable |
| `0x6ef`    | `jmp 0x704` — loop entry point                                     |
| `0x6f1`    | `nopl` — alignment NOP before the `add` write path                 |
| `0x6f8`    | `movb $0x5,(%rax)` — write `add` opcode (`0x05`) into code region  |
| `0x6fb`    | `add $0x5,%rax` — advance write pointer by 5                       |
| `0x6ff`    | `cmp %rax,%rsi` — check if write pointer reached the end           |
| `0x702`    | `je 0x71b` — loop exit if done                                     |
| `0x704`    | `mov %edx,%ecx` — save current input copy before shifting          |
| `0x706`    | `sar %edx` — arithmetic right shift: consume LSB, expose next bit  |
| `0x708`    | `and $0x1,%ecx` — isolate the bit just consumed                    |
| `0x70b`    | `test %ecx,%ecx` — is the bit 1?                                   |
| `0x70d`    | `jne 0x6f8` — yes (bit=1) → write `0x05` (add)                     |
| `0x70f`    | `movb $0x2d,(%rax)` — write `sub` opcode (`0x2d`) into code region |
| `0x712`    | `add $0x5,%rax` — advance write pointer by 5                       |
| `0x716`    | `cmp %rax,%rsi` — check end                                        |
| `0x719`    | `jne 0x704` — continue loop                                        |
| `0x71b`    | Loop exit                                                          |
| `0x742`    | `callq 0x201020` — call the self-modified code region              |
| `0x201020` | Start of generated code (`mov $0x3df2f794,%eax`)                   |
| `0x2010c5` | `cmp $0x7a612770,%eax` — final result comparison                   |
| `0x2010ca` | `sete %al` — set return value: 1 if EAX matches target             |
| `0x2010cf` | `retq` — return to caller                                          |

#### x86 Instruction Encoding (the key to everything)

| Instruction        | Opcode | Full encoding        |
| ------------------ | ------ | -------------------- |
| `add $imm32, %eax` | `0x05` | `05 [4-byte imm LE]` |
| `sub $imm32, %eax` | `0x2d` | `2d [4-byte imm LE]` |

Input bit `1` → write `0x05` (add). Input bit `0` → write `0x2d` (sub). That single byte flip is the entire mechanism.

#### Constants

| Symbol           | Value                  |
| ---------------- | ---------------------- |
| Starting EAX     | `0x3df2f794`           |
| Target EAX       | `0x7a612770`           |
| Code region size | 160 bytes (`32 × 5`)   |
| Loop iterations  | 32 (one per input bit) |
| Write stride     | 5 bytes per slot       |

#### The 32 Immediate Values

```
Index   Value
  0     0x52ae22f2
  1     0xbf409bcc
  2     0x46417dc1
  3     0x25f7d9a1
  4     0xef83a7ce
  5     0x2dd63e8e
  6     0x584a1ec5
  7     0x8e58e1df
  8     0xf2705f70
  9     0x2e94ef1e
 10     0x3ca9e080
 11     0xa617b5df
 12     0x29ae9c3d
 13     0x7461ed52
 14     0x7125faac
 15     0x65dfffd6
 16     0x97f1f41c
 17     0x6f4e0648
 18     0xd803e5d0
 19     0xf358f0eb
 20     0xbc3b30c7
 21     0x585685f8
 22     0x2a9cc47c
 23     0x7f03d175
 24     0xc1d942ae
 25     0x174c7d4f
 26     0xb7d004f0
 27     0xbec8b077
 28     0x8ce8eaa2
 29     0x2510e330
 30     0x4aed0eee
 31     0x4043cd91
```

#### How the Bit Reversal Works

The binary consumes bits LSB-first (`SAR` shifts the LSB out each iteration), so:

```
input bit 0  →  operation 0  (first add/sub in generated code)
input bit 1  →  operation 1
...
input bit 31 →  operation 31 (last add/sub in generated code)
```

The recursion builds `marker` by left-shifting and OR-ing at each level, so `marker` accumulates bits MSB-first (level 0 ends up in bit 31 of marker, level 31 in bit 0). `bitrev()` corrects this, producing the integer whose LSB-first bit stream matches the add/sub sequence that hits the target.

***

_Solved by recognising the self-modification pattern in the loop, identifying that `0x05`/`0x2d` are `add`/`sub` opcodes, extracting the 32 immediates with a GDB script, and running a recursive DFS to find all 32-bit integers whose sign-assignment of those constants evaluates to the target value._
