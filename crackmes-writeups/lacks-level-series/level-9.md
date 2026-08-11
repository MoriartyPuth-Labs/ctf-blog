# Level 9

> **Category:** Reverse Engineering (RE) / Bytecode VM password check
>
> **Difficulty:** Medium–Hard
>
> **Platform:** Windows x64&#x20;
>
> **Goal:** Enter the correct **6-letter password** to print `[+] Correct!`.

**TL;DR — the password is `matrix`.**

The password is validated by a small **stack-based virtual machine** whose 54-byte bytecode is embedded in the binary. Symbolically executing it recovers `matrix`. As in Level 6, the "decrypted flag" it prints is **garbage** (`Yu`f}l5`) because the flag's XOR key is derived from the password's byte-sum and doesn't match the blob — the intended flag was` Matrix!\`.

***

### 1. Recon

```bash
unzip -P crackmes.one 6a512af62c3088f968e1341f.zip   # -> level8.exe
file level8.exe        # PE32+ console x86-64
```

Strings:

```
       CRACKME LEVEL 8
Enter 6-Letter Password:
[+] Correct! Decrypted flag:
[-] Access Denied. Decrypted output:  (Garbage!)
```

Familiar shape (6-letter key, decrypt-and-print, "(Garbage!)" fail label), but the validation is new.

***

### 2. Finding the check

Anchor on `Enter 6-Letter Password:` → `main` at `0x140001440` (pefile + capstone). The password is read into a `std::string` at `[rbp-0x30]`. Then:

#### (a) Flag decryption (sum-keyed, with a NOT)

```asm
0x140001503  movsx eax, byte [rcx]   ; sum input bytes -> edi
0x140001506  add   edi, eax
0x140001510  not   dil               ; keybyte = ~(sum & 0xFF)
0x140001544  xor   r9b, byte [rbx]   ; flag[i] = keybyte XOR blob[i]
```

#### (b) The password validator — a bytecode VM

After a length check (`cmp r12, 6`), the code walks a byte array `[0x140006230 .. 0x140006238]` three bytes at a time, dispatching on the first byte:

```asm
0x1400015b0  movzx r8d, byte [rdx+r10+1]   ; operand
0x1400015b6  movzx eax, byte [rdx+r10]     ; opcode
0x1400015bb  sub eax, 1 ; je op1
0x1400015c0  sub eax, 1 ; je op2
0x1400015c5  cmp eax, 1 ; je op3
0x1400015ca  xor r11b, r11b               ; unknown opcode -> fail

op1 (0x1400015e6): if operand < 6: r9 = password[operand]   ; LOAD
op2 (0x1400015e1): r9 ^= operand                            ; XOR
op3 (0x1400015cf): r11b = (r9 == operand) ? r11b : 0        ; ASSERT
...
0x14000160c  test r11b, r11b
0x14000160f  je   denied                  ; all asserts must pass
```

So it's a 3-opcode VM:

| Opcode | Operand | Effect                |
| ------ | ------- | --------------------- |
| `1`    | `idx`   | `r9 = password[idx]`  |
| `2`    | `k`     | `r9 ^= k`             |
| `3`    | `v`     | `result &= (r9 == v)` |

`[+] Correct!` requires every `assert` to pass. Each `assert` pins one (possibly XOR-masked) password byte to a constant — fully invertible.

***

### 3. Extracting the bytecode

The program is a 54-byte (`0x36`) runtime-initialized global; its initializer at `0x140001070` builds it from stack immediates, e.g.:

```asm
mov dword [rbp-0x40], 0x02000001   ; 01 00 00 02
mov dword [rbp-0x3c], 0x7f030012   ; 12 00 03 7f
...
mov word  [rbp-0x0c], 0x00c4
```

Reassembling little-endian gives:

```
01 00 00 02 12 00 03 7f 00 01 01 00 02 34 00 03 55 00 01 02
00 02 56 00 03 22 00 01 03 00 02 78 00 03 0a 00 01 04 00 02
90 00 03 f9 00 01 05 00 02 bc 00 03 c4 00
```

54 bytes = **18 instructions** of 3 bytes each (opcode, operand, padding).

***

### 4. Solving by symbolic execution

Walk the program, tracking the loaded index and accumulated XOR; at each `assert` solve `password[idx] = v XOR acc`:

```python
pw = {}; cur = None
for i in range(0, len(prog), 3):
    op, operand = prog[i], prog[i+1]
    if   op == 1: cur = [operand, 0]      # load pw[operand]
    elif op == 2: cur[1] ^= operand       # xor accumulate
    elif op == 3: pw[cur[0]] = operand ^ cur[1]   # assert -> solve
password = ''.join(chr(pw[i]) for i in range(6))   # -> "matrix"
```

Decoding the 18 instructions:

```
load pw[0]; xor 0x12; assert 0x7f  -> pw[0] = 0x7f^0x12 = 0x6d 'm'
load pw[1]; xor 0x34; assert 0x55  -> pw[1] = 0x55^0x34 = 0x61 'a'
load pw[2]; xor 0x56; assert 0x22  -> pw[2] = 0x22^0x56 = 0x74 't'
load pw[3]; xor 0x78; assert 0x0a  -> pw[3] = 0x0a^0x78 = 0x72 'r'
load pw[4]; xor 0x90; assert 0xf9  -> pw[4] = 0xf9^0x90 = 0x69 'i'
load pw[5]; xor 0xbc; assert 0xc4  -> pw[5] = 0xc4^0xbc = 0x78 'x'
```

**Password = `matrix`.**

***

### 5. Verification

```bash
printf 'matrix\n\n' | ./level8.exe
```

```
       CRACKME LEVEL 8
Enter 6-Letter Password:
[+] Correct! Decrypted flag: Yu`f}l5
```

`[+] Correct!` — the password is accepted. ✅ (The trailing "flag" is garbage; see next.)

***

### 6. The garbage flag (same bug as Level 6)

Flag blob = `33 1f 0a 0c 17 06 5f`; decrypt key = `~(sum(password) & 0xFF)`:

```
sum("matrix") = 661 = 0x295  ->  0x295 & 0xFF = 0x95
keybyte       = ~0x95 = 0x6a
flag          = blob XOR 0x6a = "Yu`f}l5"     <- garbage
```

Brute-forcing the blob, the only clean plaintext is:

```
key 0x7e -> "Matrix!"     (the intended flag)
```

Key `0x7e` needs `sum & 0xFF == ~0x7e = 0x81`, but `matrix` sums to `0x95`. Since the VM forces the password to be **exactly** `matrix`, no valid input can produce key `0x7e` — the validator and the flag-key derivation are decoupled, exactly like Level 6.

**Conclusion:** the password is `matrix` (verified `[+] Correct!`); the intended flag was `Matrix!`, but it's unreachable through the correct password because of the author's key-derivation bug.

***

### Answer

| Field                | Value                                                                         |
| -------------------- | ----------------------------------------------------------------------------- |
| **Password**         | `matrix`                                                                      |
| **Validation**       | 18-instruction bytecode VM (load / xor / assert)                              |
| **Intended flag**    | `Matrix!` (key `0x7e`)                                                        |
| **Shown flag (bug)** | `Yu`f}l5`(key`0x6a`from`\~(sum & 0xFF)\`)                                     |
| **Method**           | Static disassembly (pefile + capstone), extract & symbolically execute the VM |

***

### Tools Used

| Tool             | Purpose                                                      |
| ---------------- | ------------------------------------------------------------ |
| `unzip` / `file` | Extract & identify (PE32+ x64)                               |
| Python (`re`)    | `strings` substitute                                         |
| `pefile`         | Section VAs, locate `main`, read VM + flag blob pointers     |
| `capstone`       | Disassemble the VM dispatch loop + initializers              |
| Python           | Reconstruct the 54-byte bytecode and symbolically execute it |
| the binary       | Dynamic confirmation of `[+] Correct!`                       |

***

### Takeaways / Methodology

1. **Recognize a bytecode interpreter by its dispatch shape.** A loop reading a global array N bytes at a time, with a `sub/sub/cmp`-style opcode ladder and a running result flag, is a VM — don't trace it as ad-hoc logic; recover the ISA.
2. **Three opcodes are enough to obfuscate a `strcmp`.** `load / xor / assert` is just a per-byte equality check wrapped in a mask. Once you name the opcodes, the "program" _is_ the password (inverted through the XOR masks).
3. **Symbolic execution beats brute force here.** Each `assert` yields one byte directly (`v XOR acc`); there's nothing to guess — reconstruct the bytecode and run it forward while solving.
4. **The Level-6 flag bug recurs.** The VM pins the password exactly, but the flag key comes from `~(sum & 0xFF)`, which doesn't line up with the blob. Report the real password and note the intended flag (`Matrix!`) rather than pretending the binary prints clean text.
