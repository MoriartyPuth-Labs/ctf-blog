# Level 7

> **Category:** Reverse Engineering (RE) / XOR password + decoy UI
>
> **Difficulty:** Medium
>
> **Platform:** Windows x64&#x20;
>
> **Goal:** Enter the correct **password** to print `[+] Access Granted!` and unlock the "Secret Menu".

**TL;DR — the password is `license`.**

The password check is `password[i] XOR 0x5A == expected[i]` (same primitive as Level 2). Decoding the embedded `expected` blob gives `license`. A second blob decrypts to the header banner **`Welcome to the Secret Menu!`**. Unlike Level 6, both the check and the decrypted text line up correctly — this level is _not_ bugged.

***

### 1. Recon

```bash
unzip -P crackmes.one 6a512ae1234391ae74f63aec.zip   # -> level7.exe
file level7.exe        # PE32+ console x86-64
```

Strings reveal a fake GUI on top of the real check:

```
       CRACKME LEVEL 7
Enter Password:
[+] Access Granted!
[-] Access Denied. Decrypted header:  (Garbage!)
[A] Button A            [!] Button A clicked! (Does nothing)
[B] Button B            [!] Button B clicked! (Does nothing)
[C] Button C            [!] Button C clicked! (Does nothing)
[Q] Quit
Enter Choice (A/B/C/Q):
```

The menu is a **decoy** — every button explicitly "Does nothing". It only appears _after_ the password succeeds, so it's post-win flavor, not part of the challenge. The import list also includes `toupper` (used only by the menu's choice handling, not the password check).

***

### 2. Finding the password check

Anchor on `Enter Password:` → the check lives in the function at `0x1400013e0` (pefile + capstone). The password is read into a `std::string` at `[rbp-0x28]`. Two things then happen:

#### (a) A header decryption (shown on both success and failure)

The now-familiar byte-sum-of-input primitive, keyed with `0xA5`:

```asm
0x1400014c3  movsx ecx, byte [rax]     ; sum input bytes -> edi
0x1400014c6  add   edi, ecx
0x1400014d0  xor   dil, 0xa5           ; header key = (sum & 0xFF) XOR 0xA5
0x140001500  movzx r9d, dil
0x140001504  xor   r9b, byte [rbx]     ; header[i] = key XOR blob[i]
```

#### (b) The actual password comparison

```asm
0x140001547  mov rax, [0x140007238]    ; expected end ptr
0x14000154e  mov rdx, [0x140007230]    ; expected start ptr
0x140001555  sub rax, rdx             ; rax = expected length
0x140001558  cmp r14, rax
0x14000155b  jne denied               ; length must match

loop:                                  ; rcx = index
0x14000157c  movzx eax, byte [pw + rcx]
0x140001580  xor   al, 0x5a           ; transform input byte
0x140001582  cmp   al, byte [rcx + rdx]  ; compare to expected[i]
0x140001585  jne   denied
0x14000158b  inc   rcx
0x14000158e  cmp   rcx, r14
0x140001591  jb    loop
                                       ; else: Access Granted
```

The gate is simply:

```
password[i] XOR 0x5A == expected[i]   =>   password[i] = expected[i] XOR 0x5A
```

Same XOR-0x5A primitive as Level 2 — the "expected" bytes are just the real password pre-XORed.

***

### 3. Extracting the two blobs

Both are runtime-initialized globals; their initializers sit at the top of `.text`.

**Password blob** (`0x140007230`, 7 bytes) — initializer at `0x140001000`:

```asm
mov dword ptr [rsp+0x30], 0x3f393336   ; 36 33 39 3f
mov word  ptr [rsp+0x34], 0x2934       ; 34 29
mov byte  ptr [rsp+0x36], 0x3f         ; 3f
```

Blob = `36 33 39 3f 34 29 3f`.

**Header blob** (`0x140007218`, 0x1b = 27 bytes) — initializer at `0x140001070`:

```asm
mov dword [rbp-0x20], 0x252a2311
mov dword [rbp-0x1c], 0x66232b29
mov dword [rbp-0x18], 0x32662932
mov dword [rbp-0x14], 0x1566232e
mov dword [rbp-0x10], 0x23342523
mov dword [rbp-0xc],  0x230b6632
mov word  [rbp-8],    0x3328
mov byte  [rbp-6],    0x67
```

Blob = `11 23 2a 25 29 2b 23 66 32 29 66 32 2e 23 66 15 23 25 34 23 32 66 0b 23 28 33 67`.

***

### 4. Decoding

```python
import struct
pw_blob = struct.pack('<IHB', 0x3f393336, 0x2934, 0x3f)
password = bytes(b ^ 0x5A for b in pw_blob)
print(password.decode())            # -> license

hdr = struct.pack('<IIIIIIHB',
    0x252a2311,0x66232b29,0x32662932,0x1566232e,0x23342523,0x230b6632,
    0x3328,0x67)
key = (sum(password) & 0xFF) ^ 0xA5  # sum("license")=739 -> 0xE3 -> ^0xA5 = 0x46
print(bytes(b ^ key for b in hdr))   # -> Welcome to the Secret Menu!
```

* **Password = `license`**
* **Header = `Welcome to the Secret Menu!`**

The header key `0x46` comes from `license`'s byte-sum (`739 & 0xFF = 0xE3`, `0xE3 XOR 0xA5 = 0x46`). Because the correct password's sum yields exactly the key the banner was encrypted with, the decrypted text is clean — the Level-6 bug is _not_ present here.

***

### 5. Verification

```bash
printf 'license\nQ\n' | ./level7.exe
```

```
       CRACKME LEVEL 7
Enter Password:
[+] Access Granted!

=============================
 Welcome to the Secret Menu!
=============================
[A] Button A
[B] Button B
[C] Button C
[Q] Quit
Enter Choice (A/B/C/Q):
Exiting menu...
```

Confirmed. (Note: the menu loops on unrecognized input, so pipe a `Q` to exit — an EOF alone spins "Invalid option" forever.)

***

### Answer

| Field              | Value                                                              |
| ------------------ | ------------------------------------------------------------------ |
| **Password**       | `license`                                                          |
| **Header banner**  | `Welcome to the Secret Menu!`                                      |
| **Password check** | `password[i] = expected[i] XOR 0x5A`                               |
| **Header key**     | `(sum(password) & 0xFF) XOR 0xA5` = `0x46`                         |
| **Method**         | Static disassembly (pefile + capstone), decode both embedded blobs |

***

### Tools Used

| Tool             | Purpose                                                      |
| ---------------- | ------------------------------------------------------------ |
| `unzip` / `file` | Extract & identify (PE32+ x64)                               |
| Python (`re`)    | `strings` substitute — spot the decoy menu vs the real check |
| `pefile`         | Section VAs, locate `main`, read both blob pointers          |
| `capstone`       | Disassemble the password comparison + both initializers      |
| Python           | Decode the XOR-0x5A password and the sum-keyed header        |
| the binary       | Dynamic confirmation (pipe `Q` to exit the menu)             |

***

### Takeaways / Methodology

1. **Ignore the decoy UI.** The A/B/C menu literally says "Does nothing" and only runs post-authentication — recognizing it as flavor keeps you focused on the single real gate (the password comparison).
2. **XOR-0x5A returns.** The password check is the exact Level-2 primitive: `input XOR 0x5A == embedded`. When the "expected" data is a small blob compared byte-wise, try `blob XOR <constant>` before anything fancier.
3. **Two blobs, two purposes.** One is the comparison target (the password), the other is display text keyed off the input sum. Don't conflate them — trace each pointer to its own initializer.
4. **Mind the input loop when running.** Piping just the password leaves the post-win menu reading EOF forever; always supply the quit token (`Q`) so the process terminates cleanly.
