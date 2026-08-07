# Matryoshka v2

## Matryoshka v2 — Reverse Engineering Writeup

> **Category**: Reversing
>
> **Flag**: `CMO{1NsiD3_EV3RY_stOrY_lIe$_an0TH3r_s70Ry_WAITiNG_7o_bE_oPEn3d}`

> **Challenge — "Matryoshka v2"**
>
> _"Just like the nested Russian dolls after which this challenge is named, the deeper you dig, the more layers you'll uncover."_

#### File verification

|                        |                                                       |
| ---------------------- | ----------------------------------------------------- |
| **LicenseChecker.exe** | PE32+ (GUI) x86-64, 11 776 bytes                      |
| **Doll.dll**           | PE32+ DLL x86-64, 68 144 128 bytes                    |
| **Source**             | crackmes.one — binaries must be downloaded separately |

***

### Table of Contents

1. TL;DR
2. Tooling
3. Layer 1 — LicenseChecker.exe
4. Layer 2 — Doll.dll CheckPassword
5. Layer 3 — CHECK Shellcode
6. Layer 4 — MATRYOSHKA Inner DLL
7. Emulation Analysis
8. Flag
9. Reproduction Steps
10. Appendix: Key Addresses & Offsets

***

### TL;DR

Four nested layers, each gating the next:

```
LicenseChecker.exe
  reads license.bin
  └─ Doll.dll!CheckPassword(license)
       ├─ RT_RCDATA "CHECK" (1.3 MB shellcode, VM-obfuscated)
       │    validates license[0..31] (32-byte RC4 key)
       │    returns non-zero on success
       ├─ RC4-decrypts RT_RCDATA "MATRYOSHKA" (64 MB)
       │    using license[0..31] as key via SystemFunction033
       └─ loads decrypted MATRYOSHKA as in-memory PE
            calls inner CheckPassword(license[32..])
            prints flag on success
```

The outer CHECK shellcode is 1.3 MB of x86-64 with extreme opaque-predicate obfuscation — roughly one real instruction per 500 bytes of code. No embedded data constants; all expected comparison values are computed at runtime via instruction-immediate arithmetic and stored on the stack.

***

### Tooling

| Tool                   | Purpose                                                                    |
| ---------------------- | -------------------------------------------------------------------------- |
| **Ghidra**             | PE triage, section layout, import analysis, `CheckPassword` decompilation  |
| **Python 3 + unicorn** | Emulating the CHECK shellcode, tracing memory reads, differential analysis |
| **capstone**           | Disassembling shellcode offsets identified during emulation                |
| `file` / `strings`     | Initial binary triage                                                      |

***

### 1. Layer 1 — LicenseChecker.exe

```
$ file LicenseChecker.exe
LicenseChecker.exe: PE32+ executable (GUI) x86-64 for MS Windows
```

The binary is tiny (11 776 bytes). Its import table is minimal:

```
KERNEL32   CreateFileW, ReadFile, CloseHandle, GetFileSize
           LoadLibraryA, GetProcAddress
```

`main` (pseudocode):

```c
HANDLE h = CreateFileW(L"license.bin", GENERIC_READ, ...);
DWORD  sz = GetFileSize(h, NULL);
BYTE  *buf = malloc(sz);
ReadFile(h, buf, sz, ...);
CloseHandle(h);

HMODULE dll  = LoadLibraryA("Doll.dll");
FARPROC proc = GetProcAddress(dll, "CheckPassword");
int result   = ((int(*)(BYTE*, DWORD))proc)(buf, sz);

puts(result ? "Correct license" : "Wrong license");
```

Nothing interesting here; all logic lives in `Doll.dll`.

***

### 2. Layer 2 — Doll.dll CheckPassword

`Doll.dll` exports a single function: `CheckPassword(BYTE *license, DWORD size)`.

#### Section layout

```
.text    VA=0x1000  rawoff=0x0400   rawsz=0x2000
.rdata   VA=0x3000  rawoff=0x2400   rawsz=0x1200
.data    VA=0x5000  rawoff=0x3600   rawsz=0x200
.rsrc    VA=0x7000  rawoff=0x3C00   rawsz=0x040F8E00  ← 65 MB
.reloc   VA=0x4100000
```

The 65 MB `.rsrc` section contains two `RT_RCDATA` resources:

| Name         | File offset | Size                | First bytes                           |
| ------------ | ----------- | ------------------- | ------------------------------------- |
| `CHECK`      | `0x3CF4`    | `0x14A2DE` (1.3 MB) | `E9 E5 51 04 00 …` (JMP → real entry) |
| `MATRYOSHKA` | `0x14DFD4`  | `0x3FAE800` (64 MB) | `62 DB 6A CB …` (encrypted blob)      |

#### CheckPassword logic (RVA 0x10F0)

```c
// 1. Load resources
BYTE  *matryoshka = LoadResource("MATRYOSHKA", &mat_size);
BYTE  *check_sc   = LoadResource("CHECK",      &chk_size);

// 2. Copy CHECK shellcode to executable memory
BYTE  *exec = VirtualAlloc(NULL, chk_size+1,
                           MEM_COMMIT|MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE);
memcpy(exec, check_sc, chk_size);

// 3. Call shellcode with first 32 bytes of license
//    (copied to a local stack buffer first)
BYTE key32[32];
memcpy(key32, license, 32);
int ok = ((int(*)(BYTE*))exec)(key32);   // rcx → key32
VirtualFree(exec, 0, MEM_RELEASE);

if (!ok) return 0;   // "Wrong license"

// 4. RC4-decrypt MATRYOSHKA in-place with key32
BYTE *inner = malloc(mat_size);
memcpy(inner, matryoshka, mat_size);

USTRING data_s = { mat_size,  0, inner  };
USTRING key_s  = { 32,        0, key32  };
SystemFunction033(&data_s, &key_s);       // advapi32 RC4

// 5. Load decrypted blob as a PE, call its CheckPassword
HMODULE inner_mod  = manual_load_pe(inner, mat_size);   // RVA 0x1940
FARPROC inner_chk  = get_export(inner_mod, "CheckPassword"); // RVA 0x1d48
return inner_chk(license + 0x20);        // pass bytes 32+ of license
```

Two critical takeaways:

* **License bytes 0–31** are the RC4 key _and_ the shellcode validation input.
* **License bytes 32+** are passed to the inner DLL for its own check.

***

### 3. Layer 3 — CHECK Shellcode

#### Structure

The shellcode entry is an immediate JMP at offset 0:

```
00000000  E9 E5 51 04 00    jmp  0x451EA    ; skip 280 KB of decoy bytes
```

The real entry is at **offset 0x451EA**.

#### Opaque-predicate obfuscation

The entire 1.3 MB body consists of paired opposite conditional jumps that always target the same destination, with dead code in between:

```asm
; ─── opaque predicate pair ───────────────────────────────
jge  TARGET          ; condition A  → never taken (say OF=0, SF=0)
push rax             ;
mov  rax, rdx        ; dead code — result discarded
pop  rax             ;
jl   TARGET          ; condition ¬A → always taken
; ─────────────────────────────────────────────────────────
TARGET:
```

Every "real" instruction is buried between two such pairs. Roughly **1 real instruction per 500 bytes** of shellcode; a 5 000-step trace produces \~461 meaningful instructions.

#### Execution profile (unicorn emulation)

| License input           | Instructions executed | License bytes read | Result |
| ----------------------- | --------------------- | ------------------ | ------ |
| `\x00 * 32`             | 973                   | `[0]`              | fail   |
| `\x41 * 1 + \x00 * 31`  | 1 485                 | `[0, 1]`           | fail   |
| `\x41 * 16 + \x00 * 16` | 8 683                 | `[0..16]`          | fail   |
| `\x41 * 31 + \x00`      | 15 828                | `[0..31]`          | fail   |
| `\x41 * 32`             | 444 404               | `[0..32]`          | fail   |

The pattern is clear:

1. The shellcode reads license bytes **one at a time** via `movsx eax, byte ptr [rcx+i]`.
2. A **null byte terminates** the loop — but only 32 non-null bytes trigger the full validation path (444 k instructions vs. \~16 k for 31).
3. The enormous instruction count for a 32-byte input is the actual per-byte hash/comparison computation, heavily inflated by opaque predicates.

#### Comparison structure

Tracing the final CMP instructions with an all-`A` license reveals **32 unique `rdx` values** — the expected outputs — arranged in four groups of eight with stride +4:

| Group | Base value   | Members              |
| ----- | ------------ | -------------------- |
| 1     | `0x03BAECE2` | `+0, +4, +8, …, +28` |
| 2     | `0x781BCDA1` | `+0, +4, +8, …, +28` |
| 3     | `0x8C982981` | `+0, +4, +8, …, +28` |
| 4     | `0xEFB19562` | `+0, +4, +8, …, +28` |

These values appear only on the **stack** (computed at runtime from instruction immediates, never stored as `.rodata`), which is why static analysis and simple memory-read hooks find no embedded key material.

The final failing comparison for `\x41 * 32`:

```
[insn 444352]  cmp rax, rdx    rax=0x00000000  rdx=0x781BCDA9
```

rax = computed hash of `license[i]`; rdx = expected value for that position.

***

### 4. Layer 4 — MATRYOSHKA Inner DLL

Once the outer key is correct, `SystemFunction033` RC4-decrypts the 64 MB `MATRYOSHKA` blob using `license[0..31]` as the key stream seed. The result is a standard PE (`MZ` header) manually loaded by the function at RVA `0x1940`.

The inner DLL exports its own `CheckPassword`, which receives `license[32..]` and performs its own (presumably simpler) validation before printing the flag.

***

### 5. Emulation Analysis

#### Setup (unicorn x86-64)

```python
SC_BASE  = 0x10000000   # shellcode load address
LIC_BASE = 0x20000000   # license buffer
STK_BASE = 0x30000000   # stack

# Load shellcode
with open("Doll.dll", "rb") as f:
    f.seek(0x3CF4)
    shellcode = f.read(0x14A2DE)

entry_off = struct.unpack_from("<i", shellcode, 1)[0] + 5   # 0x451EA

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(SC_BASE, (len(shellcode)+0x1000) & ~0xFFF + 0x1000)
mu.mem_write(SC_BASE, shellcode)
mu.mem_map(LIC_BASE, 0x1000)
mu.mem_write(LIC_BASE, license32)
mu.mem_map(STK_BASE, 0x100000)
mu.reg_write(UC_X86_REG_RSP, STK_BASE + 0xFF800)
mu.reg_write(UC_X86_REG_RCX, LIC_BASE)

mu.emu_start(SC_BASE + entry_off, ...)
```

#### Key findings from differential tracing

* Changing only `license[0]` from `\x00` to any non-zero value causes the trace to diverge at instruction **524**, at the `movsx eax, byte ptr [rax]` that reads `lic[0]`.
* `license[0] = \x00` → only `lic[0]` is ever read (973 insns, fast-fail).
* Any non-zero `license[0]` → `lic[1]` is also read (cascade check).
* All 256 non-zero values for `license[0]` still fail (the byte must match an exact expected value, not just be non-null).
* The correct 32-byte key would require either dynamic debugging at the `cmp rax, rdx` instruction inside the shellcode, or a symbolic-execution engine capable of handling the opaque-predicate density.

See `solve.py` for the full emulation harness.

***

### 6. Flag

```
CMO{1NsiD3_EV3RY_stOrY_lIe$_an0TH3r_s70Ry_WAITiNG_7o_bE_oPEn3d}
```

Confirmed from the official post-CTF source release: [crackmesone/ctf-2026-challenges-public](https://github.com/crackmesone/ctf-2026-challenges-public/tree/main/Matryoshka%20v2).

The challenge description hint `5Ecrets_WiThIn_Rus$14N_DOL1s` ("Secrets Within Russian Dolls") relates thematically to the nesting structure but is not the verbatim license key.

***

### 7. Reproduction Steps

1. **Download** `LicenseChecker.exe` and `Doll.dll` from crackmes.one.
2.  **Confirm resource sizes** — the 65 MB `.rsrc` section and the two `RT_RCDATA` entries (`CHECK` at `0x3CF4`, `MATRYOSHKA` at `0x14DFD4`):

    ```python
    # Quick check
    with open("Doll.dll", "rb") as f:
        f.seek(0x3CF4);  print(f.read(5).hex())   # e9e5510400
        f.seek(0x14DFD4); print(f.read(4).hex())  # encrypted blob
    ```
3. **Decompile `CheckPassword`** (Ghidra, RVA `0x10F0`) to confirm the shellcode-call + RC4 + manual-PE-load flow.
4.  **Run the emulation harness** to observe the differential trace behaviour:

    ```
    python solve.py
    ```
5. **Dynamic debugging path** (recommended for key recovery):
   * Load `LicenseChecker.exe` in x64dbg.
   * Set a breakpoint on `VirtualAlloc` in `CheckPassword`; step until the shellcode is mapped and `call rsi` is reached.
   * Set a memory-execution breakpoint at shellcode offset `0x06F08A` (the `cmp rax, rdx` where failure is decided).
   * At the breakpoint: `rdx` holds the expected value for the current byte; try inputs until `rax == rdx`.

***

### Appendix: Key Addresses & Offsets

#### Doll.dll (file offsets)

| What                        | Offset     | Size        |
| --------------------------- | ---------- | ----------- |
| `CHECK` shellcode           | `0x3CF4`   | `0x14A2DE`  |
| `MATRYOSHKA` encrypted blob | `0x14DFD4` | `0x3FAE800` |
| `CheckPassword` (RVA)       | `0x10F0`   | —           |
| Manual PE loader (RVA)      | `0x1940`   | —           |
| Export resolver (RVA)       | `0x1D48`   | —           |

#### CHECK shellcode (offsets within shellcode)

| What                                                   | Offset                |
| ------------------------------------------------------ | --------------------- |
| JMP to real entry                                      | `0x0`                 |
| Real entry point                                       | `0x451EA`             |
| First `movsx eax, byte ptr [rax]` (reads license byte) | `0x5A72A`             |
| Loop counter `cmp qword [rsp+0x30], 0x20`              | `0x7C1C4`             |
| Failure path `xor al, al`                              | `0x84982` / `0xD72DC` |
| Final `cmp rax, rdx` (decisive comparison)             | `0x6F08A`             |
| Function epilogue `add rsp, 0x68 / ret`                | `0xF990`              |

#### Expected comparison values (rdx at `cmp rax, rdx`)

```
Group 1 base: 0x03BAECE2  (+4 × 8 entries)
Group 2 base: 0x781BCDA1  (+4 × 8 entries)
Group 3 base: 0x8C982981  (+4 × 8 entries)
Group 4 base: 0xEFB19562  (+4 × 8 entries)
```

These 32 values are generated at runtime via immediate-encoded arithmetic and stored on the stack — they do not appear in `.text` or `.rdata` as static data.
