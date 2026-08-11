# Level 3

> **Category:** Reverse Engineering (RE) / Keygen
>
> **Difficulty:** Easy–Medium
>
> **Platform:** Windows x64&#x20;
>
> **Goal:** Enter a **username** and a matching numeric **serial key** to print `[+] Access Granted! You are a master keygenerator.`

**TL;DR — this is a keygen.** The serial is derived from the username:

```
serial = (sum_of_username_bytes * 1337) XOR 0x5A5A
```

Example: `admin` → `719707`. A 3-line `keygen.py` produces a valid key for any username.

***

### 1. Recon

```bash
unzip -P crackmes.one 6a512a442c3088f968e1341b.zip   # -> level3.exe
file level3.exe
# PE32+ executable (console) x86-64, for MS Windows, 6 sections
```

Strings reveal the new twist — **two** inputs instead of one:

```
       CRACKME LEVEL 3
Enter Username:
Enter Serial Key (numbers only):
[+] Access Granted! You are a master keygenerator.
[-] Access Denied. Key is invalid for this username.
```

"Key is invalid **for this username**" is the giveaway: the serial is a _function of_ the username. There's no single password to find — we need the **algorithm**, i.e. a keygen. There is no plaintext key in the binary.

***

### 2. Finding `main`

No symbols, so anchor on the `Enter Username:` string. With `pefile` + `capstone`, scan `.text` for the RIP-relative `lea` that references it — it lands inside the function at `0x1400012c0`. Walking that function:

* `std::cin >> username` (a `std::string`) at `0x14000132d`
* prints `Enter Serial Key...`
* `std::cin >> serial` **into a 32-bit int** at `[rsp+0x20]` (`0x140001345`) — so the serial is parsed as a number, not compared as text
* some validation on the stream state (rejects empty / non-numeric input)
* then the core check.

***

### 3. The core check

The interesting block (cleaned up):

```asm
; --- compute a checksum of the username bytes ---
; (compiler auto-vectorized this with SSE; the scalar tail shows intent)
0x140001443  movsx ecx, byte ptr [rax]   ; sign-extend each username byte
0x140001446  add   edx, ecx              ; edx += byte
0x140001448  inc   rax
0x14000144b  cmp   rax, r8
0x14000144e  jne   0x140001443           ; loop over all bytes
;   => edx = sum of the username's byte values

; --- derive expected serial and compare ---
0x140001450  imul  eax, edx, 0x539       ; eax = sum * 1337
0x140001456  xor   eax, 0x5a5a           ; eax ^= 0x5A5A  (23130)
0x14000145b  cmp   dword ptr [rsp+0x20], eax   ; entered serial == expected?
0x140001466  je    granted
             ...                          ; else denied
```

The big `punpcklbw / psrad / paddd` SSE stretch right above is just the vectorized version of the same signed-byte summation — the compiler unrolled the loop 8 bytes at a time. Both paths produce identical results, so we can read the simple scalar tail and ignore the vector noise.

#### Algorithm in one line

```
sum      = Σ username_bytes           (signed char; identical to ASCII sum for printable input)
expected = (sum * 0x539) XOR 0x5A5A   ; 0x539 = 1337, 0x5A5A = 23130
```

Since printable ASCII is < 128, every byte is positive and the "signed" sum is just the ordinary sum of character codes.

***

### 4. Keygen

```python
def keygen(username: str) -> int:
    s = sum(username.encode())
    return (s * 0x539) ^ 0x5A5A
```

| username | Σ bytes | serial     |
| -------- | ------- | ---------- |
| `admin`  | 521     | **719707** |
| `test`   | 448     | **620954** |
| `Level3` | 542     | **723145** |

***

### 5. Verification

```bash
printf 'admin\n719707\n\n' | ./level3.exe
```

```
=============================
       CRACKME LEVEL 3
=============================

Enter Username: Enter Serial Key (numbers only):
[+] Access Granted! You are a master keygenerator.

Press Enter to exit...
```

Confirmed.

***

### Answer

| Field       | Value                                                                      |
| ----------- | -------------------------------------------------------------------------- |
| **Type**    | Keygen (serial derived from username)                                      |
| **Formula** | `serial = (Σ username_bytes * 1337) XOR 0x5A5A`                            |
| **Example** | `admin` / `719707`                                                         |
| **Method**  | Static disassembly (pefile + capstone), read the algorithm, write a keygen |

***

### Tools Used

| Tool          | Purpose                                                    |
| ------------- | ---------------------------------------------------------- |
| `unzip`       | Extract the archive (password `crackmes.one`)              |
| `file`        | Identify format/architecture (PE32+ x64)                   |
| Python (`re`) | `strings` substitute — spot the two-input keygen prompts   |
| `pefile`      | Resolve section VAs, locate `main` via the username string |
| `capstone`    | Disassemble the checksum + serial-derivation logic         |
| `keygen.py`   | Reimplement the algorithm to generate valid serials        |
| the binary    | Dynamic confirmation of a generated key                    |

***

### Takeaways / Methodology

1. **Two inputs + "invalid for this username" = keygen.** The task isn't to find a secret; it's to recover the username→serial function.
2. **Serial parsed as an int, not a string.** The `cin >> int` tells you the comparison is numeric — no need to worry about string formatting/leading zeros.
3. **Don't fight the vectorizer.** When you see `punpcklbw/psrad/paddd`, look for the scalar remainder loop right after it — it reveals the plain-English operation (here, a byte sum) without decoding the SIMD.
4. **Constants are the recipe.** `imul …, 0x539` then `xor …, 0x5A5A` _is_ the whole algorithm; recognizing `0x539 = 1337` and `0x5A5A` makes the keygen trivial.
