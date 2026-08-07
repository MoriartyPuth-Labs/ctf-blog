# bubbly

> **Challenge — "Please find the correct input to pass the crackme!"**
>
> _"Welcome! Please provide swap indices to sort the array."_

**Solution input (22 swap indices, one per line):**

```
2
3
4
5
7
9
10
13
15
17
18
1
4
12
14
16
17
0
11
15
16
15
```

**Result:** `Well done!`

#### File Verification

|                     |                                                                    |
| ------------------- | ------------------------------------------------------------------ |
| **Filename**        | `main` (binary), `main.py` (solver script)                         |
| **main.py SHA-256** | `69d192f55d89c6de40e71386abc432cea348123c62e3730b6e71c34dbf2514e1` |
| **main.py MD5**     | `fa9bd61529ced70296b9372e363d2386`                                 |
| **Source**          | https://crackmes.one/crackme/5f0cf6b233c5d42a7c6679c8              |
| **Author**          | [jeffli6789](https://crackmes.one/user/jeffli6789)                 |

> The binary (`main`) must be downloaded from crackmes.one — it is not bundled in this repository.

```bash
# Download from crackmes.one (free account required), extract with password: crackmes.one
chmod +x main
```

***

### Table of Contents

1. TL;DR
2. Tooling
3. Initial Triage
4. Behavioural Analysis
5. The Input Loop — XOR Swap
6. The Validation Loop — Ascending Order Check
7. Putting It Together — What the Binary Actually Wants
8. The Solver — Bubble Sort
9. Full Solver (PoC)
10. Reproduction Steps
11. Confirming on the Binary
12. Appendix: Key Addresses

***

### TL;DR

The binary holds a fixed 20-element integer array and enters a loop where it reads one number at a time from stdin. Each number is treated as an index `i` — it XOR-swaps `arr[i]` and `arr[i+1]` in place. When stdin closes, it checks whether the array is sorted in ascending order. If yes: `Well done!`. If no: `Try again!`.

|                         | Detail                                                                   |
| ----------------------- | ------------------------------------------------------------------------ |
| **Array**               | `[1, 2, 6, 0, 3, 5, 4, 8, 7, 12, 9, 10, 13, 17, 11, 18, 14, 19, 16, 15]` |
| **Input format**        | One integer per line (valid range: 0–18)                                 |
| **Mechanism**           | Each integer XOR-swaps `arr[i]` with `arr[i+1]`                          |
| **Win condition**       | Array sorted ascending after all swaps                                   |
| **Strategy**            | Simulate bubble sort, emit the index `j` on every swap                   |
| **Total swaps needed**  | 22                                                                       |
| **Target sorted array** | `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]` |

The solution is the exact sequence of adjacent-swap indices that bubble sort performs on the starting array — nothing more.

***

### Tooling

| Tool                              | Purpose                                                                  |
| --------------------------------- | ------------------------------------------------------------------------ |
| `file`, `strings`                 | Initial binary triage                                                    |
| `IDA Pro` / `objdump -d -M intel` | Static disassembly — reading the swap loop and validation logic          |
| `gdb`                             | Dynamic analysis — confirming array address, watching swaps live         |
| `python3`                         | Solver script (`main.py`) — simulates bubble sort and emits swap indices |

No external Python libraries needed.

***

### 1. Initial Triage

```console
$ file main
main: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
      dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped

$ strings main | grep -E 'done|again|sort|array|input'
Well done!
Try again!
```

Key observations:

* **Dynamically linked** — unlike the Maze crackme, this binary uses `libc` (`puts`, `scanf` or similar). We can expect standard C idioms.
* **Stripped** — no function symbols, but the control flow is simple enough that this barely matters.
* **Only two outcome strings** — `Well done!` and `Try again!`. Same binary outcome pattern: pass or fail, nothing in between.
* **Small binary** — this is not a structural puzzle like Maze. The logic is in a tight loop with a comparison at the end.

***

### 2. Behavioural Analysis

```console
$ echo "5" | ./main
Try again!

$ printf "0\n1\n2\n" | ./main
Try again!

$ ./main
(waits for input — reads until EOF)
^D
Try again!
```

The binary reads integers until EOF, then makes a single pass/fail decision. No prompts, no intermediate output — just silence until the verdict. This tells me there's a loop that consumes all input first, then evaluates the result.

Trying a random sequence of swaps always fails unless the swaps happen to leave the array sorted. The binary is evaluating the _state of an internal array_ after all our swaps, not the swap sequence itself.

***

### 3. The Input Loop — XOR Swap

Disassembling around the input-handling code in IDA / objdump, the core swap block sits at `0x6A7`:

```asm
; ── called once per input number ─────────────────────────────────────────────
; rax = index read from stdin (i)
; rbx = base address of the array

.text:00000000000006A7   lea  ecx, [rax+1]         ; ecx = i+1
.text:00000000000006AA   mov  edx, eax             ; edx = i
.text:00000000000006AC   mov  eax, [rbx+rdx*4]     ; eax = arr[i]
.text:00000000000006AF   xor  eax, [rbx+rcx*4]     ; eax = arr[i] ^ arr[i+1]
.text:00000000000006B2   mov  [rbx+rdx*4], eax     ; arr[i]   = arr[i] ^ arr[i+1]
.text:00000000000006B5   xor  eax, [rbx+rcx*4]     ; eax = (arr[i]^arr[i+1]) ^ arr[i+1] = arr[i]
.text:00000000000006B8   mov  [rbx+rcx*4], eax     ; arr[i+1] = original arr[i]
.text:00000000000006BB   xor  [rbx+rdx*4], eax     ; arr[i] ^= arr[i+1] → final swap
.text:00000000000006BE   lea  rax, unk_201024       ; reload array pointer
.text:00000000000006C5   mov  ecx, [rbx]            ; ecx = arr[0] (prep for validation)
```

This is a classic **XOR swap** — swapping two values in place without a temporary variable:

```
arr[i]   ^= arr[i+1]   →   arr[i]   = A^B
arr[i+1]  = arr[i]     →   arr[i+1] = A^B ^ B = A      (original arr[i])
arr[i]   ^= arr[i+1]   →   arr[i]   = A^B ^ A = B      (original arr[i+1])
```

After those three operations, `arr[i]` and `arr[i+1]` are exchanged. The input number is simply the index `i` of the left element in the pair to swap.

> **Important:** the valid range is `0`–`18`. Providing `19` would try to swap `arr[19]` with `arr[20]`, which is out of bounds and causes undefined behaviour / crash.

***

### 4. The Validation Loop — Ascending Order Check

After the input loop exits (EOF), execution falls into the validation block starting at `0x6BE`:

```asm
; ── setup ─────────────────────────────────────────────────────────────────────
.text:00000000000006BE   lea  rax, unk_201024       ; rax = &arr[0]
.text:00000000000006C5   mov  ecx, [rbx]            ; ecx = arr[0]  (first element, "previous")

; ── ascending order check loop ────────────────────────────────────────────────
.text:00000000000006D0   mov  edx, [rax]            ; edx = arr[current]
.text:00000000000006D2   cmp  edx, ecx              ; arr[current] vs previous
.text:00000000000006D4   jb   short loc_691         ; if arr[current] < previous → NOT ascending → fail
.text:00000000000006D6   add  rax, 4                ; advance to next element
.text:00000000000006DA   mov  ecx, edx              ; ecx = arr[current] (becomes "previous")
.text:00000000000006DC   cmp  r13, rax              ; reached end of array?
.text:00000000000006DF   jnz  short loc_6D0         ; no → keep checking

; ── success ───────────────────────────────────────────────────────────────────
.text:00000000000006E1   lea  rdi, s                ; "Well done!"
.text:00000000000006E8   call _puts
```

The loop walks the array from left to right, keeping the previous element in `ecx`. For each element `edx = arr[current]`, it checks: is `edx < ecx` (i.e., did we go _down_)? If yes → `jb` to the fail branch. If we make it through every element without jumping, the array is sorted ascending → `Well done!`.

***

### 5. Putting It Together — What the Binary Actually Wants

Combining the two pieces:

1. The binary holds the array `[1, 2, 6, 0, 3, 5, 4, 8, 7, 12, 9, 10, 13, 17, 11, 18, 14, 19, 16, 15]`.
2. It reads index numbers from stdin, XOR-swapping `arr[i]` and `arr[i+1]` for each one.
3. After EOF, it checks if the array is `[0, 1, 2, ..., 19]` (ascending).

We need to provide a sequence of swap indices that **sorts the array**. Bubble sort does exactly this — it repeatedly walks the array and swaps adjacent out-of-order pairs, emitting the index of each swap. That swap sequence is the answer.

***

### 6. The Solver — Bubble Sort

Bubble sort on the starting array, printing the index `j` every time a swap happens:

**`main.py`:**

```python
arr = [1, 2, 6, 0, 3, 5, 4, 8, 7, 12, 9, 10, 13, 17, 11, 18, 14, 19, 16, 15]

for i in range(len(arr)):
    for j in range(len(arr) - i - 1):
        if arr[j] > arr[j + 1]:
            arr[j], arr[j + 1] = arr[j + 1], arr[j]
            print(j)
```

Tracing the execution pass by pass:

**Pass 0** (bubble largest to position 19):

| j  | Comparison | Swap? | Printed |
| -- | ---------- | ----- | ------- |
| 2  | 6 > 0      | ✓     | `2`     |
| 3  | 6 > 3      | ✓     | `3`     |
| 4  | 6 > 5      | ✓     | `4`     |
| 5  | 6 > 4      | ✓     | `5`     |
| 7  | 8 > 7      | ✓     | `7`     |
| 9  | 12 > 9     | ✓     | `9`     |
| 10 | 12 > 10    | ✓     | `10`    |
| 13 | 17 > 11    | ✓     | `13`    |
| 15 | 18 > 14    | ✓     | `15`    |
| 17 | 19 > 16    | ✓     | `17`    |
| 18 | 19 > 15    | ✓     | `18`    |

Array after pass 0: `[1, 2, 0, 3, 5, 4, 6, 7, 8, 9, 10, 12, 13, 11, 17, 14, 18, 16, 15, 19]`

**Pass 1** (bubble second-largest to position 18):

| j  | Comparison | Swap? | Printed |
| -- | ---------- | ----- | ------- |
| 1  | 2 > 0      | ✓     | `1`     |
| 4  | 5 > 4      | ✓     | `4`     |
| 12 | 13 > 11    | ✓     | `12`    |
| 14 | 17 > 14    | ✓     | `14`    |
| 16 | 18 > 16    | ✓     | `16`    |
| 17 | 18 > 15    | ✓     | `17`    |

Array after pass 1: `[1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 11, 13, 14, 17, 16, 15, 18, 19]`

**Pass 2** (bubble third-largest to position 17):

| j  | Comparison | Swap? | Printed |
| -- | ---------- | ----- | ------- |
| 0  | 1 > 0      | ✓     | `0`     |
| 11 | 12 > 11    | ✓     | `11`    |
| 15 | 17 > 16    | ✓     | `15`    |
| 16 | 17 > 15    | ✓     | `16`    |

Array after pass 2: `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 15, 17, 18, 19]`

**Pass 3** (one swap remaining):

| j  | Comparison | Swap? | Printed |
| -- | ---------- | ----- | ------- |
| 15 | 16 > 15    | ✓     | `15`    |

Array after pass 3: `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]` ✓ sorted

**Passes 4–19:** array already sorted, no swaps.

**Complete swap sequence (22 total):**

```
2 3 4 5 7 9 10 13 15 17 18 1 4 12 14 16 17 0 11 15 16 15
```

***

### 7. Full Solver (PoC)

```console
$ python3 main.py
2
3
4
5
7
9
10
13
15
17
18
1
4
12
14
16
17
0
11
15
16
15

$ python3 main.py | ./main
Well done!
```

***

### 8. Reproduction Steps

#### Prerequisites

```bash
# Linux x86-64 or WSL2 on Windows
python3 --version   # any Python 3.x, no extra packages needed
```

#### Step 1 — Get the binary

Download from [crackmes.one](https://crackmes.one/crackme/5f0cf6b233c5d42a7c6679c8) (free account required).\
The zip is password-protected with the standard crackmes.one password: `crackmes.one`.

```bash
unzip -P crackmes.one <downloaded>.zip
# extracts bubbly.tgz
tar -xzf bubbly.tgz
# extracts: main  main.py  write-up.txt (in the original bundle)
chmod +x main
```

#### Step 2 — Confirm baseline behaviour

```console
$ echo "0" | ./main
Try again!
```

A single arbitrary swap doesn't sort the array — expected.

#### Step 3 — Run the solver

```console
$ python3 main.py
2
3
4
5
7
9
10
13
15
17
18
1
4
12
14
16
17
0
11
15
16
15
```

#### Step 4 — Pipe the solver into the binary

```console
$ python3 main.py | ./main
Well done!
```

***

### 9. Confirming on the Binary

To watch the swaps happen live and confirm the array state, use GDB:

```bash
$ gdb ./main
```

```
(gdb) break *0x6AC          # breakpoint at: mov eax, [rbx+rdx*4]  (arr[i] load)
(gdb) run < <(python3 main.py)

Breakpoint 1, 0x00000000000006ac in ?? ()
(gdb) info registers rbx rdx rcx
rbx   0x...201020            ; base of array
rdx   0x2                    ; i = 2   (first swap index)
rcx   0x3                    ; i+1 = 3

(gdb) x/20dw $rbx            ; dump the array as 20 ints
0x...201020:  1  2  6  0  3  5  4  8  7  12  9  10  13  17  11  18  14  19  16  15

(gdb) continue               ; let all 22 swaps run
...

(gdb) x/20dw $rbx            ; dump after all swaps
0x...201020:  0  1  2  3  4  5  6  7  8  9  10  11  12  13  14  15  16  17  18  19
```

Array is fully sorted → validation loop passes → `Well done!` is printed.

***

### Appendix: Key Addresses

| Address    | Meaning                                                              |
| ---------- | -------------------------------------------------------------------- |
| `0x6A7`    | `lea ecx, [rax+1]` — compute `i+1` from input index                  |
| `0x6AC`    | `mov eax, [rbx+rdx*4]` — load `arr[i]`                               |
| `0x6AF`    | `xor eax, [rbx+rcx*4]` — first XOR with `arr[i+1]`                   |
| `0x6B2`    | `mov [rbx+rdx*4], eax` — store `arr[i] ^= arr[i+1]`                  |
| `0x6B5`    | `xor eax, [rbx+rcx*4]` — recover original `arr[i]`                   |
| `0x6B8`    | `mov [rbx+rcx*4], eax` — store `arr[i+1] = original arr[i]`          |
| `0x6BB`    | `xor [rbx+rdx*4], eax` — finalise swap: `arr[i] = original arr[i+1]` |
| `0x6BE`    | `lea rax, unk_201024` — reload array base, begin validation          |
| `0x6C5`    | `mov ecx, [rbx]` — load `arr[0]` as initial "previous"               |
| `0x6D0`    | `mov edx, [rax]` — validation loop: load current element             |
| `0x6D2`    | `cmp edx, ecx` — compare current vs previous                         |
| `0x6D4`    | `jb short loc_691` — jump if current < previous (unsorted → fail)    |
| `0x6D6`    | `add rax, 4` — advance to next element                               |
| `0x6DC`    | `cmp r13, rax` — check for end of array                              |
| `0x6DF`    | `jnz short loc_6D0` — continue loop                                  |
| `0x6E1`    | `lea rdi, s` — load `"Well done!"`                                   |
| `0x6E8`    | `call _puts` — print success                                         |
| `0x201024` | `unk_201024` — base address of the 20-element integer array          |

#### Starting Array

```
Index:  0   1   2   3   4   5   6   7   8    9  10  11  12  13  14  15  16  17  18  19
Value:  1   2   6   0   3   5   4   8   7   12   9  10  13  17  11  18  14  19  16  15
```

#### Target Array (sorted)

```
Index:  0   1   2   3   4   5   6   7   8    9  10  11  12  13  14  15  16  17  18  19
Value:  0   1   2   3   4   5   6   7   8    9  10  11  12  13  14  15  16  17  18  19
```

#### XOR Swap — How It Works

```
Before:  arr[i] = A,  arr[i+1] = B

Step 1:  arr[i]   ^= arr[i+1]   →  arr[i]   = A^B
Step 2:  arr[i+1]  = arr[i]     →  arr[i+1] = A^B ^ B = A   (original arr[i])
Step 3:  arr[i]   ^= arr[i+1]   →  arr[i]   = A^B ^ A = B   (original arr[i+1])

After:   arr[i] = B,  arr[i+1] = A   ✓
```

***

_Solved by reading the swap loop and validation logic in IDA, recognising the XOR swap pattern, and implementing bubble sort in Python to emit the exact swap-index sequence the binary expects._
