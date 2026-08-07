# CryptPad — Reverse Engineering Writeup

**Event**: `Writeups` | **Category**: `Misc`

---

# CryptPad — Reverse Engineering Writeup

> **Challenge:** "We found this on an old machine. Can you decrypt it?"
> **Files:** `cryptpad.exe`, `flag.enc`
> **Author:** crudd
> **Category:** Reverse Engineering / Crypto
> **Flag format:** `CMO{...}`

**Flag:** `CMO{r0ll_y0ur_0wn_b4d_c0d3}`

---

## TL;DR

`cryptpad.exe` is a tiny 32-bit Windows GUI "encrypted notepad." Its self-described *"custom encryption algorythm"* is really:

```
ciphertext = pre_XOR(ks)  ->  RC4(key)  ->  post_XOR(ks)
```

where the **same keystream `ks` is XORed before and after RC4**. Because XOR is commutative/associative, the two `ks` layers **cancel out**, so the whole thing reduces to plain **RC4** with an 8-byte key.

Worse: when it saves a file, the program **appends the random RC4 key to the file** in a 13-byte trailer. So the key needed to decrypt is sitting inside `flag.enc` itself. Recover the key from the trailer, run RC4, done.

---

## 1. Files & triage

```
cryptpad.exe   11,776 bytes   PE32 (x86) GUI executable
flag.enc            64 bytes   raw ciphertext
```

`flag.enc` (hex):

```
c9 98 8f c7 a6 1c 02 6b e2 06 f3 52 49 16 27 59
45 5c 4c 47 bc 4e 28 a6 2f 71 c7 d8 06 85 42 03
08 50 7d 93 f5 fe e5 99 48 4e 82 2b e2 00 57 26
16 f6 b4 1c 00 00 00 e8 17 1b f4 50 3f 3d 70 08
```

PE header facts:

| Field | Value |
|------|-------|
| Machine | `0x014c` (i386, 32-bit) |
| Magic | `0x010b` (PE32) |
| Sections | `.text` `.data` `.idata` `.rc` |
| .NET / CLR dir | none (native code) |
| ImageBase | `0x400000` |
| EntryPoint | `0x401000` |

Interesting strings:

```
CryptPad 1.0 is an encrypted notepad that uses a custom encryption algorythm ...
This option is only available in the full version.
To register, send $100,000,000,000 to: Crackmes.One, Pueblo, Colorado 80019
Encrypted Files   *.enc
```

Interesting imports (the tell):

```
ADVAPI32.DLL!SystemFunction036      <- RtlGenRandom (CSPRNG)
KERNEL32.DLL!CreateFileA / WriteFile / HeapAlloc / GetProcessHeap
USER32.DLL!GetWindowTextA / GetWindowTextLengthA
COMDLG32.DLL!GetSaveFileNameA
```

**Hypothesis (1 line):** native crackme that encrypts the note with a key derived from `SystemFunction036`; recover the algorithm and either the stored key or a known-plaintext to invert it — don't brute force.

---

## 2. Locating the crypto

Cross-referencing the imports to call sites quickly isolates the **Save/Encrypt** handler and a couple of helpers:

| Address | Role |
|---------|------|
| `0x4013bd` | Save handler (alloc buffer, `CreateFileA`, `GetWindowTextA`, encrypt, `WriteFile`) |
| `0x4014eb` | **`crypt(buf, n, dir)`** — the cipher (encrypt `dir=1`, decrypt `dir=0`) |
| `0x40166b` | thin wrapper around `SystemFunction036` (RtlGenRandom) |

### 2.1 Save handler (`0x4013bd`)

Annotated pseudocode reconstructed from the disassembly:

```c
len   = GetWindowTextLengthA(hEdit);
N     = len + 1;                          // include NUL terminator
pad   = 0x40 - (N % 0x40);                // pad up to a multiple of 64
total = N + pad;                          // == 64 here
buf   = HeapAlloc(heap, 0, total);
hFile = CreateFileA(name, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, NORMAL, 0);
GetWindowTextA(hEdit, buf, N);            // copy note text + NUL into buf

rng(buf + N, pad);                        // 0x40166b: random padding bytes
rng(0x4024c5, 8);                         // 0x40166b: generate the 8-byte KEY

crypt(buf, N, /*dir=*/1);                 // encrypt first N bytes in place
WriteFile(hFile, buf, total, &written, 0);
```

So only the **first `N` bytes** (the note + NUL) are encrypted; the remaining `pad` bytes are random filler, and a trailer is written by `crypt()` itself (see §2.4).

### 2.2 The key generator (`0x40166b`)

```asm
0040166b  push ebp / mov ebp,esp
0040166e  push [ebp+0xc]          ; length
00401671  push [ebp+8]            ; buffer
00401674  call [SystemFunction036] ; RtlGenRandom(buf, len)
0040167b  ret 8
```

The 8-byte key lives at **`0x4024c5`** in `.data`.

### 2.3 The cipher `crypt(buf, n, dir)` (`0x4014eb`)

Three stages, all operating on `buf` for `n` bytes, using the key at `0x4024c5`:

**Stage 1 — pre-XOR (`0x40154a`):**

```asm
mov esi, buf
mov edi, 0x4024c5      ; key region
mov ecx, [0x40357d]    ; = N
xor edx, edx
.loop:
  al = [esi]; bl = [edi]; al ^= bl; [esi] = al
  esi++; edi++; edx++
  if edx == 8: edx = 0          ; (edi is NOT reset -> keystream = bytes at 0x4024c5+i)
  ecx--; if ecx==0 done else loop
```

→ `buf[i] ^= ks[i]`, where `ks[i]` = byte at `0x4024c5 + i`.

**Stage 2 — RC4 (`0x40156f`–`0x40160a`):**

* `0x40156f` Identity-init S-box at `0x403795`: `S[i] = i`.
* `0x401583` Build a 256-byte key schedule at `0x403695` by **repeating the 8-byte key**: `ksched[i] = key[i % 8]`.
* `0x4015a3` Standard **RC4 KSA**:
  ```
  j = 0
  for i in 0..255: j = (j + S[i] + ksched[i]) & 0xff; swap(S[i], S[j])
  ```
* `0x4015d0` Standard **RC4 PRGA** over `n` bytes (i starts at 1):
  ```
  i = j = 0
  for k in 0..n-1:
      i = (i+1) & 0xff
      j = (j + S[i]) & 0xff
      swap(S[i], S[j])
      buf[k] ^= S[(S[i] + S[j]) & 0xff]
  ```

**Stage 3 — post-XOR (`0x40160c`):** identical to Stage 1 — `buf[i] ^= ks[i]` with the same `ks`.

### 2.4 The trailer writer (`0x401631`, only when `dir == 1`)

```c
p = buf + N + pad - 13;     // 13 bytes before end of the 64-byte block
*(uint32*)p = N;            // store N (len+1)
memcpy(p+4, 0x4024c5, 8);   // store the 8-byte KEY
p[12] = 0x08;               // marker
```

So the **last 13 bytes** of every saved file are:

```
[ uint32 N ][ 8-byte RC4 key ][ 0x08 ]
```

---

## 3. The two fatal weaknesses

1. **The XOR layers cancel.** The output is
   `P ^ ks ^ RC4ks ^ ks`. XOR is commutative, the `ks` terms cancel, leaving `P ^ RC4ks`.
   → The "custom" cipher is **just RC4** with the 8-byte key. (The pre/post XOR keystream `ks` — including the buggy non-resetting index — is completely irrelevant.)

2. **The key is stored with the ciphertext.** The trailer embeds the random RC4 key in plaintext. No brute force, no known-plaintext gymnastics needed.

---

## 4. Recovering the key from `flag.enc`

Last 13 bytes (offsets 51–63):

```
1c 00 00 00 | e8 17 1b f4 50 3f 3d 70 | 08
```

* `N`  = `0x0000001c` = **28**  → note text is 27 chars + NUL.
* key  = **`e8 17 1b f4 50 3f 3d 70`**
* marker = `0x08` ✔

Only the **first 28 bytes** are RC4 ciphertext; bytes 28–50 are random padding; bytes 51–63 are the trailer.

---

## 5. Decryption / PoC

`solve.py`:

```python
#!/usr/bin/env python3
# CryptPad solver — the cipher reduces to plain RC4; the key is stored in the file trailer.

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

ct = open("flag.enc", "rb").read()

# Trailer: [uint32 N][8-byte key][0x08]
N   = int.from_bytes(ct[-13:-9], "little")   # 28
key = ct[-9:-1]                               # e8 17 1b f4 50 3f 3d 70
assert ct[-1] == 0x08

pt = rc4(key, ct[:N])
print("N   =", N)
print("key =", key.hex())
print("flag=", pt.split(b"\x00")[0].decode())
```

Run:

```console
$ python solve.py
N   = 28
key = e8171bf4503f3d70
flag= CMO{r0ll_y0ur_0wn_b4d_c0d3}
```

Verification: the decrypted bytes are `CMO{r0ll_y0ur_0wn_b4d_c0d3}\x00` — exactly `N = 28` bytes (27 printable + NUL), matching the format `CMO{...}`. ✔

---

## 6. Full reproduction steps

1. **Unzip** the handout:
   ```bash
   unzip cryptpad_handout.zip      # -> cryptpad.exe, flag.enc
   ```
2. **Triage** the binary:
   ```bash
   file cryptpad.exe               # PE32 executable (GUI) Intel 80386
   strings -n 5 cryptpad.exe       # note "custom encryption algorythm", SystemFunction036
   ```
3. **Disassemble** and find the crypto (any of: Ghidra / IDA / radare2 / objdump / capstone). Locate:
   * Save handler `0x4013bd`
   * `crypt()` at `0x4014eb`
   * RNG wrapper `0x40166b` (RtlGenRandom)
4. **Read the algorithm:** identify pre-XOR + RC4 + post-XOR, note the XOR layers cancel, and the trailer layout `[N][key][0x08]`.
5. **Pull the key** from the last 13 bytes of `flag.enc`: `N=28`, `key=e8171bf4503f3d70`.
6. **RC4-decrypt** the first 28 bytes → `CMO{r0ll_y0ur_0wn_b4d_c0d3}`.
7. **Verify** length (`N`), NUL terminator, and flag format.

---

## 7. Tools used

| Tool | Purpose |
|------|---------|
| `unzip` / Expand-Archive | extract the handout |
| `file` / magic-byte check | identify PE32 (x86) |
| `strings` | quick triage; spotted the cipher hint + imports |
| **pefile** (Python) | parse PE header, sections, imports, RVA→offset |
| **capstone** (Python) | linear + targeted recursive x86 disassembly |
| Ghidra / IDA / radare2 | (equivalent alternative) static analysis |
| Python 3 | reimplement RC4 and decrypt |
| `xxd` / hex view | inspect `flag.enc` trailer |

> Note: the binary embeds an `SystemFunction036`-based CSPRNG, so the key is **different every save** — but since it is stored in the file trailer, that randomness provides no security here.

---

## 8. Key takeaways

* **Don't roll your own crypto.** Sandwiching RC4 between two identical XOR passes adds zero security — the layers cancel algebraically.
* **Never store the key next to the ciphertext.** A random per-file key written into the file trailer is no better than no key at all.
* For RE crypto challenges: **recover and read the algorithm**, exploit stored key material / known plaintext / structure, and cap blind brute force. Here the binary literally hands you the key.

---

### Appendix A — trailer layout of `flag.enc`

```
offset 0x00 .. 0x1b (28)  : RC4 ciphertext  (note + NUL)
offset 0x1c .. 0x32 (23)  : random padding  (RtlGenRandom)
offset 0x33 .. 0x36 ( 4)  : uint32 N         = 1c 00 00 00  (28)
offset 0x37 .. 0x3e ( 8)  : RC4 key          = e8 17 1b f4 50 3f 3d 70
offset 0x3f         ( 1)  : marker           = 08
```

### Appendix B — relevant addresses

```
0x4013bd  Save/Encrypt handler
0x4014eb  crypt(buf, n, dir)
0x40154a  pre-XOR loop
0x40156f  RC4 S-box identity init   (S at 0x403795)
0x401583  key schedule (key[i%8])   (at 0x403695)
0x4015a3  RC4 KSA
0x4015d0  RC4 PRGA
0x40160c  post-XOR loop
0x401631  trailer writer [N][key][0x08]
0x40166b  rng() -> ADVAPI32!SystemFunction036 (RtlGenRandom)
0x4024c5  8-byte key (.data)
```
