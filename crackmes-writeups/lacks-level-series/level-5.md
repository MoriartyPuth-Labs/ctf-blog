# Level 5

> **Category:** Reverse Engineering (RE) / Keygen + XOR decryption
>
> **Difficulty:** Medium
>
> **Platform:** Windows x64&#x20;
>
> **Goal:** Enter a **username** + numeric **serial** so the program prints `[+] Success! Your decrypted flag is: <flag>` — where the flag decrypts to real text.

**TL;DR**

* Correct serial: **`serial = (sum of username bytes) × 123`**
* The serial's low byte also decrypts a hidden flag: `key = (serial & 0xFF) XOR 0x34`
* Encrypted blob `34 08 0b 11 02 03 46` → **flag `Solved!`** (key `0x67`)
* To get _Success **and** the readable flag_, the username's byte-sum must be **≡ 9 (mod 256)**.
* Working combos: **`admin` / `64083`** or **`ddA` / `32595`**

***

### 1. Recon

```bash
unzip -P crackmes.one 6a512a5e71ee08cad748dcb2.zip   # -> level4.exe
file level4.exe        # PE32+ console x86-64
```

Strings show a new idea — the program _decrypts and prints a flag_ on both success and failure:

```
       CRACKME LEVEL 4
Enter Username:
Enter Serial Key (numbers only):
[+] Success! Your decrypted flag is:
[-] Access Denied. Decrypted output:
```

So this is Level 3's keygen **plus** a serial-driven decryption routine. Same two inputs (username + numeric serial), but now the serial is also a decryption key.

***

### 2. Finding `main` and the serial check

Anchor on `Enter Username:` → `main` is at `0x140001330` (pefile + capstone). The username is read into a `std::string`, the serial into a 32-bit int at `[rbp-0x50]`.

The serial-validation part is identical in spirit to Level 3 — an (auto-vectorized) sum of the username's bytes, then:

```asm
0x1400014be  imul r12d, r8d, 0x7b      ; r12d = sum * 123   (expected serial)
...
0x140001547  mov  eax, [rbp-0x50]      ; eax = entered serial
0x140001551  cmp  eax, r12d
0x140001554  jne  denied               ; Success iff serial == sum*123
```

So **`serial = sum × 123`** grants "Success" — that part is a plain keygen.

***

### 3. The new part — serial-driven flag decryption

Between the checksum and the final compare, the serial's low byte is turned into an XOR key and used to decrypt a 7-byte blob:

```asm
0x1400014c2  mov   eax, [rbp-0x50]     ; entered serial
0x1400014c5  movzx esi, al            ; sil = serial & 0xFF
0x1400014c8  xor   sil, 0x34          ; key = (serial & 0xFF) XOR 0x34
...
; loop over encrypted blob [0x140006218 .. 0x140006220):
0x140001500  movzx r9d, sil
0x140001504  xor   r9b, byte [rbx]    ; decrypted = key XOR blob[i]
0x140001521  mov   [out+rcx], r9b     ; append to output string
```

Two facts fall out of this:

1. The decryption key comes from the **entered serial**, not the computed one — so the displayed flag depends only on what serial you type (mod 256), independent of the pass/fail check.
2. The blob is a fixed global `std::string` at `[0x140006218]`.

#### Extracting the blob

`0x140006218` lives past `.data`'s raw size, so it's a runtime-initialized global. Its initializer (at `0x140001000`) builds the bytes as stack immediates:

```asm
0x140001004  mov ecx, 7                             ; length 7
0x140001009  mov dword ptr [rsp+0x30], 0x110b0834   ; 34 08 0b 11
0x140001011  mov word  ptr [rsp+0x34], 0x302        ; 02 03
0x140001018  mov byte  ptr [rsp+0x36], 0x46         ; 46
```

Blob = `34 08 0b 11 02 03 46`.

***

### 4. Recovering the flag

The decryption is a single-byte XOR, so brute-force all 256 keys and keep the printable result:

```python
blob = bytes([0x34,0x08,0x0b,0x11,0x02,0x03,0x46])
for k in range(256):
    d = bytes(b ^ k for b in blob)
    if all(32 <= c < 127 for c in d):
        print(hex(k), d)
```

The obvious hit:

```
0x67 -> Solved!
```

**The flag is `Solved!`, encrypted with key `0x67`.**

***

### 5. Tying it together — which username/serial?

For the program to _display_ `Solved!`, the runtime key must equal `0x67`:

```
key = (serial & 0xFF) XOR 0x34 = 0x67
   => serial & 0xFF = 0x67 XOR 0x34 = 0x53  (83)
```

And to also get **Success**, the serial must equal `sum × 123`. Combining:

```
(sum × 123) mod 256 == 0x53
  123 is invertible mod 256; solving gives  sum mod 256 == 9
```

So: pick any username whose byte-sum ≡ 9 (mod 256), then enter `serial = sum × 123`.

* `admin` → sum 521 (521 mod 256 = 9 ✓) → serial `521 × 123 = 64083`
* `ddA` → sum 265 (≡ 9) → serial `32595`

Usernames that _don't_ satisfy the congruence still print "Success" (the serial is valid) but show a **garbage** flag, because the decryption key is wrong. Example — `test` (sum 448) / `55104` prints `[+] Success! Your decrypted flag is: @|evw2`.

***

### 6. Verification

```bash
printf 'admin\n64083\n\n' | ./level4.exe
```

```
=============================
       CRACKME LEVEL 4
=============================

Enter Username: Enter Serial Key (numbers only):
[+] Success! Your decrypted flag is: Solved!

Press Enter to exit...
```

Confirmed.

***

### Answer

| Field                            | Value                                                                             |
| -------------------------------- | --------------------------------------------------------------------------------- |
| **Flag**                         | `Solved!`                                                                         |
| **Serial formula**               | `serial = (Σ username_bytes) × 123`                                               |
| **Flag key**                     | `(serial & 0xFF) XOR 0x34` = `0x67` for the real flag                             |
| **Constraint for readable flag** | `Σ username_bytes ≡ 9 (mod 256)`                                                  |
| **Example**                      | `admin` / `64083` → `Solved!`                                                     |
| **Method**                       | Static disassembly (pefile + capstone), extract blob, brute XOR, solve congruence |

***

### Tools Used

| Tool             | Purpose                                                          |
| ---------------- | ---------------------------------------------------------------- |
| `unzip` / `file` | Extract & identify (PE32+ x64)                                   |
| Python (`re`)    | `strings` substitute — spotted the "decrypted flag" prompts      |
| `pefile`         | Section VAs, locate `main`, read blob pointers                   |
| `capstone`       | Disassemble serial check + XOR-decrypt loop + blob initializer   |
| Python           | Brute-force the 1-byte XOR key; solve `sum×123 ≡ 0x53 (mod 256)` |
| `keygen.py`      | Generate username/serial and preview the decrypted flag          |
| the binary       | Dynamic confirmation                                             |

***

### Takeaways / Methodology

1. **Serial-as-key is a common escalation.** Level 3's `sum×K` keygen returns, but now the serial doubles as a decryption key — recognize when a check value is _reused_ downstream.
2. **The displayed output can be independent of the pass/fail branch.** Here the flag is decrypted from the _entered_ serial before the comparison, so "Success" and "readable flag" are two separate conditions.
3. **Single-byte XOR = brute all 256.** Never guess the key; the printable-ASCII filter finds it instantly (`Solved!`).
4. **Turn constraints into modular arithmetic.** Requiring both `serial == sum×123` and `serial & 0xFF == 0x53` reduces to `sum ≡ 9 (mod 256)` — then any username meeting it works.
