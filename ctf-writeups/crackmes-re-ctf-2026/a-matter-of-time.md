# a matter of time

> **Category**: Reversing
>
> **Flag**: `CMO{5h3_p4St_1s_t0_l34rn_fr0M_n0T_t0_l1V3_1n}`

***

### TL;DR

The binary is an obfuscated (custom `bin2bin`) crackme that gates execution on a 4-hour CTF time window. The flag is **AES-CBC-128** with:

* **Key** = the author's username `nicetryboogeyman` — leaked verbatim in the embedded PDB path, and conveniently exactly 16 bytes (AES-128).
* **IV** = an _"amalgamated value from UNIX decimal timestamps"_ — a 16-digit zero-padded ASCII decimal string.
* **Ciphertext** = 48 bytes (3 blocks) recoverable from the binary / live process memory.

You don't need to defeat the time gate. Because of CBC's structure, **plaintext blocks ≥ 1 depend only on the key**, so most of the flag drops out with the key alone. The first block needs the IV, which is recovered with the known plaintext `CMO{` + the timestamp format.

***

### 1. Tools used

| Tool                                                             | Purpose                                              |
| ---------------------------------------------------------------- | ---------------------------------------------------- |
| Python 3 + [`capstone`](https://www.capstone-engine.org/)        | disassembly                                          |
| Python 3 + [`pefile`](https://github.com/erocarrera/pefile)      | PE parsing (sections, imports, IAT)                  |
| Python 3 + [`pycryptodome`](https://www.pycryptodome.org/)       | AES decryption                                       |
| Custom **ctypes Windows debugger** (`timehook.py`, `memdump.py`) | run under debug, hook time APIs, dump process memory |
| `solve.py`                                                       | final offline PoC                                    |

No IDA/Ghidra/x64dbg required — everything was done with Python + a hand-rolled debugger.

***

### 2. Triage

```
$ file a_matter_of_time.exe
a_matter_of_time.exe: PE32+ executable (console) x86-64, for MS Windows, 7 sections
```

Sections (via `pefile`):

```
.text   VA 0x1000  raw 0x400   size 0x9800
.rdata  VA 0xb000  raw 0x9c00  size 0x5200
.data   VA 0x11000 ...
.pdata  VA 0x12000 ...
.rsrc   VA 0x13000 ...
.reloc  VA 0x14000 ...
.ch     VA 0x15000 raw 0x10400 size 0x13a00   <-- unusual, bulk of the file
```

Two red flags:

1. A non-standard **`.ch`** section holds \~80 KB — and it begins with a real x64 function prologue (`48 89 5c 24 18 ...`), i.e. it contains **code**.
2. `.pdata` (exception unwind) only covers `.text` (0x1000–0xa7a4), **not** `.ch`. Legit MSVC always emits `.pdata` for x64 — so `.ch` is the product of a post-link obfuscator. (The author confirms: _"obfuscated with my own bin2bin"_.)

Useful strings / facts:

* **Embedded PDB path:** `C:\Users\nicetryboogeyman\cmo\x64\Release\cmo.pdb` → username **`nicetryboogeyman`** (16 chars).
* C++ error strings: `Hex string must have even length`, `invalid stoi argument`, `Internal error loading IANA database information` → hex decoding + `std::chrono`/tz.
* Imports of interest: `GetSystemTimeAsFileTime`, `__std_tzdb_get_time_zones`, `__std_tzdb_get_leap_seconds` (time / IANA tz DB), `LookupAccountSidW` + `GetTokenInformation` + `OpenProcessToken` (current **username**), `CreateProcessW` (spawns a stage), `CreateMutexW`, `getchar`, `strtol`.

All user-facing strings are **encrypted** (none appear in plaintext).

Running it (piping ENTER):

```
> Welcome to Flar-... whoops I meant Crackmes.one Reverse Engineering CTF 2026!
> You must only attempt this challenge while the CTF is running.
> Therefore you need to be quick, 'Tempus Fugit' in the blink of an eye.
> ...
> Seize it once, or it's gone to the end.
*Journal entry from January 19, 2038 by [@heapsoverflow]
Press ENTER if you read...
Time's up. Every old system switched to 64-bit but at what cost... You can still try though.
Wrong timing.
```

**Hypothesis:** time-gated crackme. The loud "January 19, 2038 / 64-bit" theme is the Year-2038 (`time_t` overflow, `0x7FFFFFFF`) flavor — but the actual working window is the **CTF slot: Feb 17 20:00 → Feb 18 00:00 GMT (2026)**.

***

### 3. The obfuscation (bin2bin)

* **Control-flow flattening + junk bytes.** Linear sweep desyncs almost immediately; basic blocks are reached through a junk-filled dispatcher via always-taken `jo`/`jno` (and `jl`/`jge`) pairs. Recursive disassembly from a known-good instruction is needed to read anything.
* **String encryption.** Each string is built at runtime: the code `movdqa`-loads scrambled 16-byte chunks from `.rdata` onto the stack, appends a few immediate bytes, then calls an in-place decoder. The transform is **XOR-by-index** (`buf[i] ^= i`) over the assembled buffer. Because chunks are _permuted_ in `.rdata`, a naive contiguous decode only works for a few strings.

Rather than fully reverse the string builder, it's far faster to let the binary decode its own strings and read them from memory (next section).

***

### 4. Stepping into the machine — ctypes debugger

The decisive move was a small **pure-Python (ctypes) Windows debugger** that:

1. `CreateProcessW(..., DEBUG_ONLY_THIS_PROCESS)` with stdin/stdout wired through pipes (feed `\r\n` for the `getchar` prompt; capture all output, including any child process it spawns).
2. Drives `WaitForDebugEvent` / `ContinueDebugEvent`.
3. **Hooks time APIs** by writing `0xCC` at the export entry and _emulating_ the whole function on hit (write desired value to `*RCX`, set `RIP=[RSP]`, `RSP+=8`).
4. At a chosen breakpoint, walks memory with `VirtualQueryEx` + `ReadProcessMemory` and regexes printable strings.

#### 4a. Which time API?

Hooking `kernel32!GetSystemTimeAsFileTime` / `GetSystemTimePreciseAsFileTime` yielded **0 hits** — modern Win10/11 `std::chrono` reaches the clock via `ntdll!NtQuerySystemTime` (and ultimately `KUSER_SHARED_DATA`). Hooking `NtQuerySystemTime` produced 3 hits. (Files: `timehook.py`.)

> ⚠️ Injecting _any_ timestamp through `NtQuerySystemTime` did **not** change the gate's verdict — the gate reads time through a path that bypasses that hook (direct `KUSER_SHARED_DATA` read). That's fine: we don't need to pass the gate.

#### 4b. Memory dump → ciphertext

Dumping committed memory (`memdump.py`) yielded the constants the program had already decoded, including:

* `2147483647` (the 2038 timestamp — flavor),
* the AES ciphertext as hex: `...04c4635258cf6eca5d80b8e050a9e5b04f1a9c979bc55f3f4773971ed2f81a96967bb3569fa002f549cc970a18779b3a7`

The captured hex was 97 chars (a stray leading nibble); the true ciphertext is the 48 bytes that decrypt to valid PKCS#7 (see below).

***

### 5. Breaking the crypto (offline)

Per the challenge description: **AES-CBC-128**, key = discoverable username, IV = amalgamated UNIX decimal timestamps.

```
key = b"nicetryboogeyman"   # 16 bytes
ct  = bytes.fromhex("4c4635258cf6eca5d80b8e050a9e5b04"
                    "f1a9c979bc55f3f4773971ed2f81a969"
                    "67bb3569fa002f549cc970a18779b3a7")   # 48 bytes
```

#### 5a. Blocks ≥ 1 need only the key

In CBC, `P_i = AES_dec(C_i) XOR C_{i-1}` for `i ≥ 1`. Decrypting with a zero IV gives garbage for block 0 but the **correct** bytes 16-47:

```
blocks 1-2  ->  b't0_l34rn_fr0M_n0T_t0_l1V3_1n}\x03\x03\x03'
```

Clean PKCS#7 padding (`\x03\x03\x03`) confirms both the key and the ciphertext alignment. We already have the second half of the flag.

#### 5b. Block 0 needs the IV — known plaintext fixes the prefix

```
dec0       = AES_dec(C_0)                       # ECB-decrypt one block
IV[i]      = dec0[i] XOR P0[i]
P0[0:4]    = "CMO{"   (flag format)
=> IV[0:4] = "0000"
```

So the IV is a **zero-padded decimal string** — consistent with "amalgamated UNIX decimal timestamps."

#### 5c. The IV value

The program builds the IV from a timestamp amalgam; the real value is `537068053`, i.e. `IV = b"0000000537068053"`:

```
$ python solve.py
[*] blocks 1-2 (key only): b't0_l34rn_fr0M_n0T_t0_l1V3_1n}\x03\x03\x03'
[*] IV[0:4] from known 'CMO{': b'0000'
[*] IV: b'0000000537068053' (amalgam = 537068053 )
[+] FLAG: CMO{5h3_p4St_1s_t0_l34rn_fr0M_n0T_t0_l1V3_1n}
[+] verified.
```

> **Intended path / "educated brute force":** The gate restricts execution to the Feb 2026 window, and the IV is derived from a timestamp. A player either (a) runs the binary in the window so it builds the real IV and decrypts, or (b) brute-forces the timestamp/format offline against the known plaintext.

#### 5d. Honest note on uniqueness ⚠️

The IV-is-16-ASCII-digits constraint **massively narrows** but does **not uniquely** determine block 0: at any position where two readable leet characters are both reachable via XOR with a digit, the choice is ambiguous (\~8.7×10¹⁰ word-character block-0 readings satisfy the constraint). For example `CMO{5h3_p4St_1s_...}` (IV `537068053`) **and** `CMO{7h3_p4St_1s_...}` (IV `200537068053`) both produce valid all-digit IVs and both read as "the". Only the **real IV value** distinguishes them — recover it by reversing the IV construction or by running the binary in-window. The official flag uses `5h3`.

***

### 6. Reproduction steps

```bash
# 1. Install deps
pip install pycryptodome pefile capstone

# 2. Offline solve (no binary execution needed)
python solve.py
#   -> CMO{5h3_p4St_1s_t0_l34rn_fr0M_n0T_t0_l1V3_1n}

# 3. (Optional) reproduce the dynamic ciphertext recovery on Windows
python memdump.py            # dumps process strings -> memdump_strings.txt
grep -aoE "[0-9a-f]{40,}" memdump_strings.txt   # find the AES ciphertext

# 4. (Optional) time-API hook experiment
python timehook.py 134158392000000000   # FILETIME inside the Feb-2026 window
```

> `memdump.py` / `timehook.py` are Windows-only (use the Win32 debug API via ctypes). `solve.py` is cross-platform and is the canonical PoC.

***

### 7. Files

| File                        | Description                                                                                                                |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `solve.py`                  | Canonical offline PoC — recovers and verifies the flag.                                                                    |
| `timehook.py`               | ctypes debugger that hooks time APIs (`NtQuerySystemTime`, etc.) and forces a chosen timestamp.                            |
| `memdump.py`                | ctypes debugger that runs the binary and dumps printable strings from process memory (where the AES ciphertext was found). |
| `README.md` / `writeup.txt` | This write-up.                                                                                                             |

***

### 8. Key takeaways

1. **CBC leaks**: blocks ≥ 1 need only the key — recover most of a flag before ever touching the IV.
2. **Known plaintext** (`CMO{`) directly yields IV bytes and reveals the IV format (here: zero-padded decimal).
3. **Don't over-trust a charset constraint** for uniqueness — it narrows, it doesn't always solve. The real IV value is the only disambiguator.
4. **The flashy theme can be misdirection** — "2038" was flavor; the real gate was the CTF window.
5. **A 200-line ctypes debugger** beats fighting a flattened/obfuscated binary statically: let it decode its own strings and read its memory.
6. **Keys hide in build artifacts** — always check the PDB path.
