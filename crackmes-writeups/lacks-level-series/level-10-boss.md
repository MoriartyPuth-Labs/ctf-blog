# Level 10 (BOSS)

> **Category:** Reverse Engineering (RE) / Hash inversion + threading obfuscation
>
> **Difficulty:** Hard
>
> **Platform:** Windows x64&#x20;
>
> **Goal:** Enter a password whose base-31 hash equals the target, printing `[+] Correct! Decrypted flag: Perfect!`.

**TL;DR**

* The password check is a **base-31 polynomial hash** (Java `String.hashCode`): `h = h*31 + c` over int32, computed in a worker **thread**. It must equal **`0x3D17141A`**.
* It's a hash, so infinitely many strings work. One valid whitespace-free preimage: **`!St3r{`**.
* The flag decrypts to **`Perfect!`** — and unlike Levels 6/8/9, the winning password produces the _clean_ flag. This level is **not** bugged.

***

### 1. Recon

```bash
unzip -P crackmes.one 6a512b2d71ee08cad748dcbe.zip   # -> level10.exe
file level10.exe        # PE32+ console x86-64
```

Strings: `CRACKME LEVEL 10 (BOSS)`, `Enter Password:`, `[+] Correct! Decrypted flag:`. The import table is the tell — **`_beginthreadex`, `_Mtx_lock`, `_Mtx_unlock`, `_Thrd_join`, `_Cnd_do_broadcast_at_thread_exit`**. The validation is offloaded to a thread.

***

### 2. Following the threading

`main` (at `0x1400013a0`) reads the password into a `std::string`, then at `0x14000143e` calls a routine that spawns a worker via `_beginthreadex` and joins it. The surrounding `cmp [rbp-1], 0` / `fastfail` checks and the mutex/`call_once` calls are **scaffolding** — they guard a `std::call_once` and validate the thread handle, but do no crypto.

The worker thread's body is the function at `0x140001300`:

```asm
0x140001306  xor ebx, ebx                 ; h = 0
; (rcx -> std::string; resolve SSO vs heap data pointer + length)
loop:
0x140001330  movsx eax, byte [rdx]        ; c = (signed char) password[i]
0x140001333  inc rdx
0x140001336  imul ebx, ebx, 0x1f          ; h *= 31
0x140001339  add ebx, eax                 ; h += c
0x14000133b  cmp rdx, rcx
0x14000133e  jne loop
...
0x140001386  mov [0x140006278], ebx       ; store hash in a global
```

That's the entire secret: **`h = h*31 + c` for each byte, int32** — Java's `String.hashCode`. The result lands in a global at `0x140006278`.

Back in `main`, after the join:

```asm
0x140001517  mov eax, [0x140006278]       ; the computed hash
0x140001524  cmp eax, 0x3d17141a          ; target
0x140001529  jne denied                   ; else Correct!
```

So we need any password with `hashCode == 0x3D17141A`.

***

### 3. The flag (correctly wired this time)

Just before the compare, the flag blob is decrypted with a key taken from the **stored hash**:

```asm
0x14000149a  mov eax, [0x140006278]       ; the hash
0x14000149a  movzx esi, al                ; low byte
0x1400014a3  xor sil, 0xaa                ; key = (hash & 0xFF) XOR 0xAA
0x1400014d4  xor r9b, byte [rbx]          ; flag[i] = key XOR blob[i]
```

Blob (`0x140006280`, 8 bytes) from its initializer at `0x140001000`:

```asm
mov dword [rsp+0x30], 0xd6c2d5e0   ; e0 d5 c2 d6
mov dword [rsp+0x34], 0x91c4d3d5   ; d5 d3 c4 91
```

Blob = `e0 d5 c2 d6 d5 d3 c4 91`. With a correct hash `0x3D17141A` → low byte `0x1A` → key `0x1A XOR 0xAA = 0xB0`:

```
blob XOR 0xB0 = "Perfect!"
```

**Because the flag key is derived from the very value the check compares, the correct password&#x20;**_**always**_**&#x20;produces the clean flag `Perfect!`.** This is the design Levels 6/8/9 got wrong — the finale gets it right.

***

### 4. Inverting the hash (meet-in-the-middle)

31 is odd, so it's invertible mod 2³², and countless strings collide onto any target. To get a printable, **whitespace-free** preimage (whitespace matters — `std::cin >> string` stops at spaces), split a 6-char password into two 3-char halves. For `password = P (3) + S (3)`:

```
hash(P + S) = hash(P) * 31**3 + hash(S)   (mod 2**32)
```

Build a table of all 3-char prefix hashes, then for each 3-char suffix solve the required prefix hash `(target - hash(S)) * inv(31**3)` and look it up:

```python
M = 1<<32; TARGET = 0x3D17141A
B3 = pow(31,3,M); invB3 = pow(B3,-1,M)
rng = range(0x21, 0x7f)                     # printable, no whitespace
pref = {}
for a,b,c in product(rng,rng,rng):
    pref.setdefault(h3((a,b,c)), (a,b,c))
for a,b,c in product(rng,rng,rng):
    need = ((TARGET - h3((a,b,c))) % M) * invB3 % M
    if need in pref:
        password = bytes(pref[need] + (a,b,c)); break
# -> b'!St3r{'
```

**Password = `!St3r{`** (one of infinitely many). Any string you find that hashes to `0x3D17141A` is equally valid.

***

### 5. Verification

```bash
printf '!St3r{\n' | ./level10.exe
```

```
    CRACKME LEVEL 10 (BOSS)
Enter Password:
[+] Correct! Decrypted flag: Perfect!
```

Confirmed — clean flag. ✅

***

### Answer

| Field        | Value                                                                                  |
| ------------ | -------------------------------------------------------------------------------------- |
| **Password** | `!St3r{` (any preimage of the hash works)                                              |
| **Check**    | `hashCode(password) == 0x3D17141A`, base-31 int32, computed in a worker thread         |
| **Flag**     | `Perfect!` (correctly decrypts on the winning path — no bug)                           |
| **Flag key** | `(hash & 0xFF) XOR 0xAA` = `0xB0`                                                      |
| **Method**   | Static disassembly (pefile + capstone), recover the hash, invert by meet-in-the-middle |

***

### Tools Used

| Tool             | Purpose                                                            |
| ---------------- | ------------------------------------------------------------------ |
| `unzip` / `file` | Extract & identify (PE32+ x64)                                     |
| Python (`re`)    | `strings` substitute; the threading imports flagged the design     |
| `pefile`         | Section VAs, locate `main` + the thread worker, read the flag blob |
| `capstone`       | Disassemble the worker's hash loop and the compare                 |
| Python           | Meet-in-the-middle inversion of the base-31 hash                   |
| the binary       | Dynamic confirmation of `[+] Correct!`                             |

***

### Takeaways / Methodology

1. **Threading can be pure obfuscation.** `_beginthreadex` + mutex/`call_once` scaffolding looked intimidating, but the actual check was a single loop in the worker. Find the thread entry point and read _its_ body — don't get lost in the synchronization glue.
2. **Recognize `h*31 + c` on sight.** Base-31 int32 folding is Java's `String.hashCode`; the `imul reg, reg, 0x1f` is the fingerprint. Naming it immediately reframes the task as hash inversion.
3. **Hashes have many preimages — invert, don't brute.** Meet-in-the-middle (split, table one half, solve the other via the modular inverse of `31**k`) yields a preimage instantly. There's no single "the" password.
4. **Mind `cin >> string` whitespace.** A first solution containing a space was silently truncated and rejected; excluding `0x20` (and other whitespace) from the character set fixed it. Match your solver's alphabet to how the program actually reads input.
5. **The finale fixes the recurring flag bug.** Here the flag key is derived from the _same_ value the check compares, so the winning password deterministically yields the real flag (`Perfect!`) — the correct way to wire a "decrypt on success" scheme.
