# FLRSCRNSVR

> **Category**: Reversing
>
> **Flag**: `CMO{frogt4s7ic_r3vers1ng}`

> **Challenge — "FLRSCRNSVR"**
>
> _"It's just a screensaver. What could it possibly be hiding?"_

#### File verification

|                     |                                                                    |
| ------------------- | ------------------------------------------------------------------ |
| **Filename**        | `FLRSCRNSVR.SCR`                                                   |
| **Format**          | PE32+ (GUI) x86-64, Windows screensaver                            |
| **Writeup SHA-256** | `0a1206e32d904cf99bed020be215dd9dedadb54b4e820c23a87dbc583100f250` |
| **Writeup MD5**     | `ac297b72402b21ed8909bb7716aab93b`                                 |
| **Source**          | crackmes.one — binary must be downloaded separately                |

> **Note:** The `.SCR` binary is not bundled with this writeup. Download it from crackmes.one and verify the hash before running on a Windows machine.

***

### Table of Contents

1. TL;DR
2. Tooling
3. Initial Triage
4. Command-line Parsing
5. Registry Architecture
6. Win Condition
7. `handling_input` Deep Dive
8. The Quak Value
9. Inverting the Transform
10. Full Solver (PoC)
11. Reproduction Steps
12. Confirming the Flag
13. Appendix: Key Addresses

***

### TL;DR

A Windows screensaver that asks for a 25-character password entered through a registry value. On launch with `/c`, a configuration dialog reads from `HKCU\Software\FLRSCRNSVR\Text`. If the entry is exactly 25 characters, the binary runs it through a three-step transform and compares the result against a hardcoded `Quak` value.

The transform is fully invertible, so we recover the flag directly by running `Quak` backwards through the inverse pipeline.

| Step | Forward (input → ciphertext)              | Reverse (ciphertext → flag)         |
| ---- | ----------------------------------------- | ----------------------------------- |
| 1    | Substitution: `str1 → str2` per-character | Inverse substitution: `str2 → str1` |
| 2    | XOR each char with `i + FLARERALF[i % 9]` | Same XOR again (self-inverse)       |
| 3    | Reverse the 25-element array              | Same reversal (self-inverse)        |

**Flag:** `CMO{frogt4s7ic_r3vers1ng}`

***

### Tooling

| Tool                                    | Purpose                                                                 |
| --------------------------------------- | ----------------------------------------------------------------------- |
| **Ghidra**                              | Main decompiler — function recovery, data-flow analysis, type inference |
| **Python 3**                            | Inverting the three-step transform to recover the flag                  |
| `file`                                  | PE header triage (format, architecture, subsystem)                      |
| **Windows Registry Editor** (`regedit`) | Verifying registry key creation and inspecting the `Quak` value         |

***

### 1. Initial Triage

```
$ file FLRSCRNSVR.SCR
FLRSCRNSVR.SCR: PE32+ executable (GUI) x86-64 for MS Windows
```

The `.SCR` extension identifies this immediately as a **Windows screensaver** — a standard PE executable that the OS invokes with specific command-line flags. Screensavers are regular binaries; Windows simply passes them a mode argument:

| Flag         | Mode                               |
| ------------ | ---------------------------------- |
| `/s` or `-s` | Run the screensaver                |
| `/c` or `-c` | Show the configuration dialog      |
| `/p` or `-p` | Preview in a small embedded window |

Dropping the binary into Ghidra and running auto-analysis gives us a recoverable function list. The import table immediately narrows the attack surface:

```
ADVAPI32.DLL   — RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, RegCreateKeyExW
GDI32.DLL      — graphics primitives
USER32.DLL     — window and dialog management
KERNEL32.DLL   — system calls, memory management
MSIMG32.DLL    — image rendering
VCRUNTIME140   — wide-string runtime: wcsncmp, wcschr, wcscpy_s, wcscat_s
```

The `ADVAPI32` registry imports stand out. The binary is reading and writing to the Windows registry — that is where both the input and the encrypted target live.

***

### 2. Command-line Parsing

The entry point calls `GetCommandLineW()` and scans the argument string using `wcschr` to find `/` or `-` prefixes:

```c
arg = wcschr(cmdline, L'/');
if (arg == NULL)
    arg = wcschr(cmdline, L'-');

if (arg) {
    wchar_t mode = towlower(*(arg + 1));
    switch (mode) {
        case L's': screensaver_mode();  break;
        case L'c': handle_box_c();      break;   // <-- our path
        case L'p': preview_mode();      break;
    }
}
```

The `/c` branch (`handle_box_c`, `FUN_140001f30`) opens a dialog where the user types their password. This is our entry point.

***

### 3. Registry Architecture

The binary uses two registry values under `HKEY_CURRENT_USER\Software\FLRSCRNSVR`:

| Value  | Type                   | Purpose                                          |
| ------ | ---------------------- | ------------------------------------------------ |
| `Text` | `REG_SZ` (wide string) | User's password input — 25 chars expected        |
| `Quak` | `REG_BINARY`           | 50 bytes — encrypted target the input must match |

**`set_default_value_in` (`FUN_140001ae0`)** is the gatekeeper function:

1. Opens `HKCU\Software\FLRSCRNSVR` with `RegOpenKeyExW`
2. Reads `Text` via `RegQueryValueExW`
3. Checks `wcslen(Text) == 0x19` (exactly **25 wide characters**)
4. If the length matches, calls `handling_input(Text)` — the three-step cipher
5. Calls `create_value` to fetch the `Quak` target from registry
6. Compares processed `Text` against `Quak` with `wcsncmp(Text, Quak, 0x19)`
7. On match: sets `DAT_140008898 = 1` (the success flag)

**`create_value` (`FUN_140001890`)** checks whether the `Quak` key already exists. If not, it calls `RegSetValueExW` to write the 50-byte hardcoded target into the registry, then returns it. The Quak value is always present once the binary has been run at least once with `/c`.

***

### 4. Win Condition

The comparison is a plain wide-string equality check:

```c
handling_input(Text, 0x19);               // transform in-place
create_value(Quak);                       // fetch or create Quak in registry
int r = wcsncmp(Text, Quak, 0x19);       // must be 0
if (r == 0)
    DAT_140008898 = 1;                    // you win
```

So the problem reduces to: find a 25-character string `X` such that `handling_input(X) == Quak`. Since `handling_input` is invertible, we compute `X = handling_input⁻¹(Quak)` directly.

***

### 5. `handling_input` Deep Dive

`FUN_140001300` applies three sequential in-place operations to the 25-element wide-character buffer.

#### Step 1 — Substitution cipher

Two 66-character alphabet strings are embedded as wide-string literals:

```
str1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-"
str2 = "-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
```

Each input character is found in `str1` (via `wcschr`), its index is recorded, and the character is replaced with `str2[index]`:

```c
for (i = 0; i < 0x19; i++) {
    wchar_t *p = wcschr(str1, input[i]);
    input[i] = str2[p - str1];
}
```

This is a simple monoalphabetic substitution. The two strings are paired at each position — `str1[k]` maps to `str2[k]`.

#### Step 2 — XOR with FLARERALF + index offset

A 9-byte XOR key is hardcoded as the wide string `"FLARERALF"`:

```
FLARERALF = 46 4c 41 52 45 52 41 4c 46   (ASCII bytes: F L A R E R A L F)
```

Each character is XORed with `(i + FLARERALF[i % 9])`, where `i` is the zero-based index:

```c
for (i = 0; i < 0x19; i++) {
    input[i] ^= (short)i + FLARERALF[i % 9];
}
```

The 9-byte key repeats cyclically, and the per-index offset `i` shifts the contribution at each position so no two positions share the same effective key byte.

#### Step 3 — Reverse

The entire 25-element array is reversed in-place:

```c
for (i = 0; i < 0xC; i++) {        // 0xC = 12 = floor(25/2)
    wchar_t tmp  = input[i];
    input[i]     = input[0x18 - i]; // 0x18 = 24
    input[0x18 - i] = tmp;
}
```

After this step, `input[0]` holds what was originally `input[24]`, and so on.

***

### 6. The Quak Value

The encrypted target is the 50-byte value written to `HKCU\Software\FLRSCRNSVR\Quak`. As raw UTF-16LE bytes:

```
3c 00 51 00 6a 00 09 00 02 00 07 00 25 00 03 00
30 00 08 00 04 00 29 00 68 00 24 00 01 00 24 00
18 00 6b 00 77 00 0f 00 70 00 36 00 02 00 0e 00
0b 00
```

Unpacked as 25 unsigned 16-bit little-endian values:

```python
[60, 81, 106, 9, 2, 7, 37, 3, 48, 8, 4, 41, 104, 36, 1, 36,
 24, 107, 119, 15, 112, 54, 2, 14, 11]
```

This is what `handling_input(flag)` produces — and what we invert to get the flag back.

***

### 7. Inverting the Transform

Each step of `handling_input` is individually invertible. We apply them in reverse order:

**Undo step 3 — reverse again:** Reversal is self-inverse; reversing twice returns the original order.

```python
quak.reverse()
```

**Undo step 2 — XOR again:** XOR is self-inverse with the same key: `x ^ k ^ k == x`.

```python
for i in range(len(quak)):
    quak[i] ^= i + flareralf[i % 9]
```

**Undo step 1 — inverse substitution:** Build the reverse map `str2 → str1` and look up each character:

```python
inv_sub = dict(zip(str2, str1))
flag = "".join(inv_sub[chr(v)] for v in quak)
```

***

### 8. Full Solver (PoC)

See `solve.py` in this folder.

```python
import struct

quak_hex = (
    "3c 00 51 00 6a 00 09 00 02 00 07 00 25 00 03 00 "
    "30 00 08 00 04 00 29 00 68 00 24 00 01 00 24 00 "
    "18 00 6b 00 77 00 0f 00 70 00 36 00 02 00 0e 00 "
    "0b 00"
)
quak_bytes = bytes.fromhex(quak_hex.replace(" ", ""))
flareralf  = bytes.fromhex("464c41524552414c46")   # "FLARERALF"

str1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-"
str2 = "-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
inv_sub = dict(zip(str2, str1))

quak = list(struct.unpack("<25H", quak_bytes))
quak.reverse()                                   # undo step 3

for i in range(len(quak)):
    quak[i] ^= i + flareralf[i % len(flareralf)]  # undo step 2

flag = "".join(inv_sub[chr(v)] for v in quak)   # undo step 1
print(flag)
```

**Output:**

```
CMO{frogt4s7ic_r3vers1ng}
```

***

### 9. Reproduction Steps

1. **Download** `FLRSCRNSVR.SCR` from crackmes.one.
2.  **Optional — register the screensaver** to explore the dialog:

    ```
    FLRSCRNSVR.SCR /c
    ```

    This opens the configuration dialog, initializes `HKCU\Software\FLRSCRNSVR\Text` with a default value, and creates the `Quak` registry key on first run.
3.  **Inspect the Quak value** in Registry Editor:

    ```
    Computer\HKEY_CURRENT_USER\Software\FLRSCRNSVR\Quak
    ```

    The 50-byte binary blob should match the hex above.
4.  **Run the solver** to recover the flag offline — no binary needed:

    ```
    python solve.py
    ```
5.  **Verify** by entering the flag string in the configuration dialog and clicking OK. If `DAT_140008898` is set to 1, the binary accepts it.

    Alternatively, write the flag directly into the registry and check the result:

    ```powershell
    Set-ItemProperty -Path "HKCU:\Software\FLRSCRNSVR" -Name "Text" `
        -Value "CMO{frogt4s7ic_r3vers1ng}"
    ```

***

### 10. Confirming the Flag

Running `solve.py`:

```
$ python solve.py
CMO{frogt4s7ic_r3vers1ng}
```

The output is exactly 25 characters — matching the `wcslen == 0x19` gate in `set_default_value_in`.

**Round-trip check for the first four characters (`CMO{`):**

To manually verify, trace `handling_input("CMO{...")` through all three steps and confirm it produces the leading Quak bytes `[60, 81, 106, 9, ...]`.

| Char | str1 index | After sub (str2 char) | Code point |
| ---- | ---------- | --------------------- | ---------- |
| `C`  | 28         | `M`                   | 77         |
| `M`  | 38         | `C`                   | 67         |
| `O`  | 40         | `A`                   | 65         |
| `{`  | 64         | `}`                   | 125        |

After XOR with index + FLARERALF and then reversal, those four values end up as the _last four_ entries in Quak before reversal — i.e., positions 21–24 of the pre-reversed array — matching `[2, 14, 11, ...]` from the Quak tail. The full 25-element round-trip confirms the flag.

***

### Appendix: Key Addresses

| Address         | Ghidra Name            | Description                                                  |
| --------------- | ---------------------- | ------------------------------------------------------------ |
| `FUN_140001300` | `handling_input`       | Three-step cipher: substitution → XOR → reverse              |
| `FUN_140001ae0` | `set_default_value_in` | Reads `Text` from registry; length check; drives win compare |
| `FUN_140001f30` | `handle_box_c`         | `/c` dialog box handler — saves user input, triggers check   |
| `FUN_140001890` | `create_value`         | Reads or creates `Quak` in `HKCU\Software\FLRSCRNSVR`        |
| `DAT_140008898` | success flag           | Set to `1` when `wcsncmp(Text, Quak, 25) == 0`               |
| `DAT_140008980` | screensaver\_mode      | Set to `1` during `/s` screensaver mode                      |
