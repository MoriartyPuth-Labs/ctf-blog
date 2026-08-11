# Level 2

> **Category:** Reverse Engineering (RE)
>
> **Difficulty:** Easy
>
> **Platform:** Windows x64 **Goal:** Recover the secret key that prints `[+] Access Granted! You solved it.`

**TL;DR — the secret key is `reverse`.**

Unlike Level 1, the key is **not** stored as a plaintext string. It's built on the stack as obfuscated bytes and checked with a per-character `XOR 0x5A`. We recover it statically by disassembling the check and undoing the XOR — no debugger, no brute force.

***

### 1. Recon

Same archive convention (crackmes.one zips use the password `crackmes.one`):

```bash
unzip -P crackmes.one 6a5129c471ee08cad748dcae.zip
# -> level2.exe

file level2.exe
# level2.exe: PE32+ executable (console) x86-64, for MS Windows, 6 sections
```

64-bit Windows console app, \~19 KB. Another "enter the secret" prompt.

***

### 2. Strings — and why they're not enough this time

Dump printable strings (Python one-liner stands in for `strings`):

```python
import re
data = open('level2.exe','rb').read()
for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
    print(m.group().decode())
```

Relevant output:

```
=============================
       CRACKME LEVEL 2
=============================
Enter Secret Key:
[+] Access Granted! You solved it.
[-] Access Denied. Try again.
Press Enter to exit...
```

**Key difference from Level 1:** there is _no_ candidate secret sitting in the string table. The imports are also different — no `std::string` `operator==`, just `strlen` and `memcpy`. That's the signal that the comparison is done **manually, byte-by-byte, against data that isn't a plain string**. Time to read the code.

***

### 3. Locating the check

The binary has no symbols, so we anchor on a string we _do_ know. The prompt `Enter Secret Key:` lives in `.rdata`; find the code that references it and we've found `main`.

Using `pefile` + `capstone`, resolve the section layout, then scan `.text` for a RIP-relative `lea` pointing at that string's virtual address:

```
ImageBase 0x140000000
.text  VA 0x140001000
.rdata VA 0x140003000   (holds the UI strings)
.data  VA 0x140005000
```

The reference lands at `0x140001371`, inside the function at `0x140001300`. Disassembling the comparison loop:

```asm
; expected key is a range [start, end) of bytes
0x140001395  mov  rax, [0x140005220]   ; end pointer
0x14000139c  mov  r8,  [0x140005218]   ; start pointer
0x1400013a3  sub  rax, r8              ; rax = expected length
...
0x1400013b0  mov  rdx, [rsp+0x30]      ; rdx = input length
0x1400013b5  cmp  rdx, rax
0x1400013b8  jne  fail                 ; length must match first

loop:                                  ; rax = index
0x1400013ce  movzx ecx, byte [input + rax]
0x1400013d2  xor   cl, 0x5a            ; <-- transform input byte
0x1400013d5  cmp   cl, byte [r8 + rax] ; compare to expected[i]
0x1400013d9  jne   fail
0x1400013db  inc   rax
0x1400013de  cmp   rax, rdx
0x1400013e1  jb    loop
```

The whole algorithm in one line:

```
(input[i] XOR 0x5A) == expected[i]   for every i
```

So to forge a valid key we just invert it: **`input[i] = expected[i] XOR 0x5A`**. Now we need `expected[]`.

***

### 4. Recovering the expected bytes

`expected` is pointed to by `[0x140005218]` (start) / `[0x140005220]` (end). Those addresses are in `.data` but **past the section's raw size** — meaning they're uninitialized on disk and filled in at runtime by a static initializer (a global string built during CRT startup). Reading the file bytes there gives nothing.

So we find the initializer instead — scan `.text` for the instruction that _writes_ `0x140005218`. It's at `0x140001026`, and the surrounding code builds the bytes as stack immediates before copying them into the heap buffer:

```asm
0x140001000  sub  rsp, 0x28
0x140001004  mov  ecx, 7                              ; length = 7
0x140001009  mov  dword ptr [rsp+0x30], 0x3f2c3f28    ; bytes 0-3
0x140001011  mov  word  ptr [rsp+0x34], 0x2928        ; bytes 4-5
0x140001018  mov  byte  ptr [rsp+0x36], 0x3f          ; byte 6
0x14000101d  call 0x140001cb0                         ; allocate
0x140001026  mov  [0x140005218], rax                  ; store start ptr
0x140001038  mov  [rax], ecx                          ; write the 7 bytes
...
```

Reassembling those immediates little-endian gives the 7 expected bytes:

```
0x3f2c3f28 -> 28 3f 2c 3f
0x2928     -> 28 29
0x3f       -> 3f
=> 28 3f 2c 3f 28 29 3f
```

***

### 5. Decode

XOR each expected byte with `0x5A`:

```python
enc = bytes.fromhex('283f2c3f28293f')
print(bytes(b ^ 0x5A for b in enc).decode())
```

| expected | ^0x5A | char |
| -------- | ----- | ---- |
| 0x28     | 0x72  | r    |
| 0x3f     | 0x65  | e    |
| 0x2c     | 0x76  | v    |
| 0x3f     | 0x65  | e    |
| 0x28     | 0x72  | r    |
| 0x29     | 0x73  | s    |
| 0x3f     | 0x65  | e    |

Result: **`reverse`**

***

### 6. Verification

```bash
printf 'reverse\n\n' | ./level2.exe
```

```
=============================
       CRACKME LEVEL 2
=============================

Enter Secret Key:
[+] Access Granted! You solved it.

Press Enter to exit...
```

Confirmed.

***

### Answer

| Field           | Value                                                      |
| --------------- | ---------------------------------------------------------- |
| **Secret Key**  | `reverse`                                                  |
| **Obfuscation** | Per-byte `XOR 0x5A` against a stack-built byte array       |
| **Method**      | Static disassembly (pefile + capstone) + inverting the XOR |

***

### Tools Used

| Tool          | Purpose                                                     |
| ------------- | ----------------------------------------------------------- |
| `unzip`       | Extract the archive (password `crackmes.one`)               |
| `file`        | Identify format/architecture (PE32+ x64)                    |
| Python (`re`) | `strings` substitute — confirm there's no plaintext key     |
| `pefile`      | Parse PE headers, resolve section VAs, read data at any RVA |
| `capstone`    | x86-64 disassembly of the check + initializer               |
| the binary    | Dynamic confirmation of the recovered key                   |

Equivalent GUI tooling: Ghidra / IDA / Binary Ninja would show the same loop decompiled. For a check this small, a scripted capstone pass is faster than opening a full disassembler.

***

### Takeaways / Methodology

1. **No plaintext secret ≠ dead end.** Absence of `std::string`/`strcmp` and presence of `strlen`/`memcpy` is a fingerprint of a hand-rolled, byte-wise comparison.
2. **Anchor on known strings.** With no symbols, find `main` by locating the `lea` that references a UI string you already see printed.
3. **Read the transform, then invert it.** The moment you see `xor cl, 0x5A; cmp cl, [expected]`, you don't need the plaintext key in the file — `key[i] = expected[i] XOR 0x5A`.
4. **Runtime-initialized globals live in code, not data.** When a `.data` pointer sits past the raw section size, stop reading the file there and go find the initializer that fills it — the constant bytes are usually `mov`-immediates on the stack.
