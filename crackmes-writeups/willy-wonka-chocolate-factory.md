# Willy Wonka Chocolate Factory

###

> **Category:** Reversing Engineering
>
> **Difficulty:** Hard

### Summary

**ChocolateFactory.exe** is a 64-bit Windows console crackme that prompts the user for a **16-character "Golden Ticket"** in the format `XXXX-XXXX-XXXX-XXXX`. The binary validates the ticket through four independent cryptographic checks, each named after a station in a chocolate factory. All four must pass to print `PASS`.

***

### Reversing Pipeline

```
 ┌──────────────┐    ┌──────────────┐    ┌─────────────────────┐
 │  file +      │    │  Input Parse │    │  Anti-Debug         │
 │  strings     │───▶│  & Guards    │───▶│  Bypass Analysis    │
 │  (Recon)     │    │  0x140002870 │    │  (IsDebuggerPresent)│
 └──────────────┘    └──────────────┘    └──────────┬──────────┘
                                                    │
              ┌─────────────────────────────────────┘
              │
              ▼
 ┌────────────────────────────────────────────────────────────┐
 │                  4-Stage Validation                        │
 │                                                            │
 │  [S-Box]──▶[Dot-Product]──▶[Hash Transform]──▶[CRC-16]    │
 │  Ch0c        M1lk             CrMe              !(L>       │
 └──────────────────────────────┬─────────────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  Keygen + PASS  🎫    │
                    │  Ch0c-M1lk-CrMe-!(L> │
                    └───────────────────────┘
```

***

### Technical Analysis

#### Initial Reconnaissance

```bash
# Identify binary format
$ file ChocolateFactory.exe
PE32+ executable (console) x86-64, for MS Windows, 6 sections

# Hunt for embedded strings
$ strings ChocolateFactory.exe | grep -i ticket
Enter your Golden Ticket (16 characters, format XXXX-XXXX-XXXX-XXXX):
```

**Key strings recovered:**

| String                      | Role                                       |
| --------------------------- | ------------------------------------------ |
| `HELPHELPHELPHELP` / `HELP` | Blacklisted inputs                         |
| `WONKWONKWONKWONK`          | Easter egg — prints a hint, does not solve |
| `Cocoa Plantation`          | Validation station 1                       |
| `Milk River`                | Validation station 2                       |
| `Caramel Oven`              | Validation station 3                       |
| `Packaging Line`            | Validation station 4                       |
| `PASS` / `FAIL`             | Outcome strings                            |

> Image base: `0x140000000` (standard PE32+ default). Sections: `.text .rdata .data .pdata .fptable .reloc`

***

#### Input Parsing & Guards

All validation logic lives at **`VA 0x140002870`**. Before the four checks run, input is sanitised through a gauntlet of guards:

| Guard             | Detail                                                                   |
| ----------------- | ------------------------------------------------------------------------ |
| **Normalisation** | Dashes (`0x2D`) and spaces (`0x20`) stripped                             |
| **Length Check**  | Stripped input must be exactly **16 chars**                              |
| **Easter Egg**    | `WONKWONKWONKWONK` → hint printed, exits without solving                 |
| **Blacklist**     | `HELPHELPHELPHELP`, `HELP`, all-zero strings — rejected via `strcasecmp` |
| **Timing Gate**   | `GetTickCount()` — must solve within **120 seconds** of launch           |

After guards pass, the 16 bytes are laid out in memory (relative to `rsp`):

```
rsp+0x30..0x33  →  ticket[ 0.. 3]   Group 1
rsp+0x34..0x37  →  ticket[ 4.. 7]   Group 2
rsp+0x38..0x3B  →  ticket[ 8..11]   Group 3
rsp+0x3C..0x3F  →  ticket[12..15]   Group 4
```

***

#### Validation Stations

***

**Station 1 — Cocoa Plantation `S-Box Substitution`**

> Code: `0x140002DFC` – `0x140002E6C`

Each of the 4 bytes in **Group 1** is looked up in a 256-byte bijective S-Box at `VA 0x14001B560`:

```
r14d = (r14d << 8) | LUT[ ticket[i] XOR mask ]
```

**Anti-Debug Trap:** The XOR mask is derived from `IsDebuggerPresent()` + `PEB.NtGlobalFlag`:

* Clean run → mask = `0x00` (no obfuscation)
* Under debugger → mask = `0x42` → every lookup changes → Check 1 **always fails**

> You cannot set a breakpoint and read the expected value — it's only reachable in a clean run.

**Target constant:** `0xC3811DEB`

Reversing the S-Box bijection byte by byte:

| Target Byte | `LUT⁻¹` | ASCII |
| ----------- | ------- | ----- |
| `0xC3`      | 67      | `C`   |
| `0x81`      | 104     | `h`   |
| `0x1D`      | 48      | `0`   |
| `0xEB`      | 99      | `c`   |

```
✅ GROUP 1 = "Ch0c"   (unique valid ASCII solution)
```

***

**Station 2 — Milk River `Dot-Product mod 256`**

> Code: `0x140002E83` – `0x140002F7F`

Uses **SSE4.1 `PMULLD`** to solve 4 simultaneous linear equations over **ℤ/256ℤ**:

```
3·t4 + 7·t5 + 2·t6 + 5·t7  ≡  0x2D  (mod 256)
5·t4 + 3·t5 + 8·t6 + 1·t7  ≡  0xDF  (mod 256)
2·t4 + 9·t5 + 1·t6 + 4·t7  ≡  0x6B  (mod 256)
6·t4 + 1·t5 + 4·t6 + 7·t7  ≡  0x9C  (mod 256)
```

Coefficient table at `VA 0x14001B660`: `[3,7,2,5, 5,3,8,1, 2,9,1,4, 6,1,4,7]`

Brute-force over printable ASCII yields one unique solution:

| var | dec | ASCII |
| --- | --- | ----- |
| t4  | 77  | `M`   |
| t5  | 49  | `1`   |
| t6  | 108 | `l`   |
| t7  | 107 | `k`   |

```
✅ GROUP 2 = "M1lk"   (unique valid printable ASCII solution)
```

***

**Station 3 — Caramel Oven `Hash Transform`**

> Code: `0x140002FA1` – `0x140003028`

A multi-step 16-bit transform on **Group 3** bytes with `rotl16`, XOR mixing, and byte swapping:

```python
# Note: bytes 8–11 are stored with a swap (b10,b11 at rsp+0x20)
r8d  = (b10 << 8) | b11
t89  = (b8  << 8) | b9

temp = (r8d - 0x3502) & 0xFFFF
temp = rotl16(temp, 5)
temp = (temp * 0x7A69) & 0xFFFF
cx   = temp

edx  = t89 ^ (cx >> 7) ^ cx
edx2 = (edx & 0xFFFF) << 16

temp2 = (edx - 0x3F40) & 0xFFFF
temp2 = rotl16(temp2, 5)
temp2 = (temp2 * 0x7A69) & 0xFFFF

ebx  = temp2 ^ (temp2 >> 7) ^ r8d | edx2

# Target: ebx == 0x016CB7CB
```

Brute-force over printable ASCII:

| var | dec | ASCII |
| --- | --- | ----- |
| b8  | 67  | `C`   |
| b9  | 114 | `r`   |
| b10 | 77  | `M`   |
| b11 | 101 | `e`   |

```
✅ GROUP 3 = "CrMe"   (unique valid printable ASCII solution)
```

***

**Station 4 — Packaging Line `CRC-16/CCITT`**

> Function: `VA 0x1400025F0`, called from `0x140003055`

The CRC seed is derived from the XOR of byte sums across the first three groups:

```python
init = (sum(G1) ^ sum(G2) ^ sum(G3)) & 0xFF   # = 0x0C
cx   = (~init) & 0xFFFF                         # = 0xFFF3
```

Each byte of Group 4 is fed through a CRC-16/CCITT step (poly `0x1021`, 8 iterations):

```python
def crc16_step(val):
    for _ in range(8):
        if val & 0x8000: val = ((val << 1) ^ 0x1021) & 0xFFFF
        else:            val = (val << 1) & 0xFFFF
    return val
```

**Target:** Final residual must equal `0x0000`

**Key insight:** `crc16_step(0) = 0` — so after processing `G4[0..2]`, the intermediate `cx2` must have a zero low byte. Then `G4[3] = cx2 >> 8`, forcing the final step to process `0x0000`.

| Byte   | Hex    | ASCII |
| ------ | ------ | ----- |
| G4\[0] | `0x21` | `!`   |
| G4\[1] | `0x28` | `(`   |
| G4\[2] | `0x4C` | `L`   |
| G4\[3] | `0x3E` | `>`   |

```
✅ GROUP 4 = "!(L>"   (~1,200+ valid solutions exist; 202 are pure alphanumeric)
```

***

### Keygen Algorithm

Groups 1–3 are **fully determined** (unique ASCII solutions). Group 4 is generatable from any seed:

```python
# Fixed groups
G1 = [0x43, 0x68, 0x30, 0x63]   # "Ch0c"
G2 = [0x4D, 0x31, 0x6C, 0x6B]   # "M1lk"
G3 = [0x43, 0x72, 0x4D, 0x65]   # "CrMe"

def generate_g4(b12, b13):
    init = (sum(G1) ^ sum(G2) ^ sum(G3)) & 0xFF
    cx   = crc16_step((~init & 0xFFFF) ^ (b12 << 8))
    ax   = crc16_step((b13 << 8) ^ cx)

    # Scan for b14 such that low byte of result == 0
    for b14 in range(256):
        cx2 = crc16_step((b14 << 8) ^ ax)
        if (cx2 & 0xFF) == 0:
            b15 = (cx2 >> 8) & 0xFF
            return [b12, b13, b14, b15]

# Build final serial
ticket = G1 + G2 + G3 + generate_g4(0x21, 0x28)
serial = f"{''.join(chr(b) for b in G1)}-{''.join(chr(b) for b in G2)}-" \
         f"{''.join(chr(b) for b in G3)}-{''.join(chr(b) for b in ticket[12:])}"
print(serial)   # → Ch0c-M1lk-CrMe-!(L>
```

***

### Golden Ticket

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   Station          Group    Algorithm         Status     ║
║   ─────────────────────────────────────────────────────  ║
║   Cocoa Plantation  Ch0c    S-Box  0xC3811DEB    ✓       ║
║   Milk River        M1lk    Dot-Product mod 256  ✓       ║
║   Caramel Oven      CrMe    Hash   0x016CB7CB    ✓       ║
║   Packaging Line    !(L>    CRC-16 residual 0x0  ✓       ║
║                                                          ║
║              Ch0c-M1lk-CrMe-!(L>                        ║
║                        PASS 🎫                           ║
╚══════════════════════════════════════════════════════════╝
```

***

### Tools Used

| Tool                           | Purpose                                       |
| ------------------------------ | --------------------------------------------- |
| `objdump`                      | Disassembly & section mapping                 |
| Python 3                       | Constraint solving, brute-force, keygen       |
| Static Analysis                | ISA tracing, anti-debug bypass identification |
| `ChocolateFactory_keygen.html` | Self-contained browser-based keygen           |

***

### Disclaimer

> This writeup is for **educational purposes only**. The binary was analysed entirely statically in an isolated environment. All techniques are intended to support learning about reverse engineering, custom cryptographic validation, and anti-debugging methods.

***
