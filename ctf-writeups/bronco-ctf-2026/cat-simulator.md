# Cat Simulator

> **Category**: Reversing
>
> **Flag**: `bronco{fluffy_baby}`

> Make the purrfect choices over 5 days to win your owner's heart… and maybe something more? Meow carefully.

### Files

* `cat-sim-linux` — ELF 64-bit x86-64, stripped, dynamically linked (the one analyzed here)
* `cat-sim-mac` — Mach-O arm64 build of the same game
* `cat-sim-windows.exe` — PE32 build of the same game

All three are the same game recompiled per-platform; only the Linux binary was needed.

### Tools

* `file` — identify binary format
* Python 3 + [`pyelftools`](https://pypi.org/project/pyelftools/) — parse the ELF section table
* Python 3 + [`capstone`](https://www.capstone-engine.org/) — disassemble `.text`
* Custom string-annotator (`scripts/disasm_cat.py`) to resolve `lea reg, [rip+disp]` targets against `.rodata` inline in the disassembly

### Approach

#### Step 1 — Recon

```
$ file cat-sim-linux
cat-sim-linux: ELF 64-bit LSB pie executable, x86-64, ... stripped
```

Stripped, no debug symbols. Extracting printable strings (PowerShell one-liner, since `strings` wasn't available) surfaced the game's dialogue plus one very suspicious partial string sitting right in `.rodata`:

```
bonco{almost_the
```

That's a **decoy** — note it's missing the `r` (`bonco` not `bronco`) and cuts off mid-word. It's meant to bait a `strings`-only attempt into submitting a wrong flag.

#### Step 2 — Disassemble and annotate

Ran `scripts/disasm_cat.py` to disassemble `.text` with capstone and inline-resolve every RIP-relative `lea` against `.rodata`, turning raw addresses into readable string references:

```
$ python scripts/disasm_cat.py > dis.txt
```

This reconstructs the game's structure at a glance:

* A day loop (6 iterations: `cmp rbx, 6` / `jne`) presenting 3 choices per day (Talk +25, Scratch −50, Eat +20 — mnemonics guessed from the score deltas in the `imm` operands next to each prompt string).
* After the loop, a chain of gates checks: zero "confused" (invalid) turns, `talk_count == 3`, `eat_count == 1`, `scratch_count == 1`, `score == 45`, and — critically — the sum of the lengths of the three typed "Talk" messages must equal exactly **32** characters.
* Passing every gate reaches a previously-unreached block at `0x1422` that builds a keystream and XORs it against an embedded ciphertext at `.rodata+0x2390`, then prints the result as the "owner's" reply.

#### Step 3 — Reverse the flag decoder

The decoder block (`0x1422`–`0x14c9`) is a straightforward keyed stream cipher over a 19-byte ciphertext:

```c
seed = r15d * 0x11;                 // r15d is a hidden accumulator (+7 per Talk, +2 per
                                     //  Eat, -12 per Scratch); the win-gate forces r15d==21
H     = lowbias32( seed ^ 0xc47b4cd0 );   // integer hash (murmur3-style finalizer)

r9  = 0x9e3779b9;                   // Weyl sequence constant
r10 = 0x5a;                         // simple additive counter
for (k, prev) in enumerate(ciphertext):
    edi  = H ^ r9
    r9  -= 0x61c88647
    edi  = rotl(edi, k % 13)
    edi ^= r10
    r10 += 0x33
    edi ^= prev
    flag[k] = edi & 0xff
```

The important realization: **the typed talk messages never touch the flag bytes at all** — the only thing that matters for the flag's _content_ is the hidden accumulator `r15d`, and the win-condition arithmetic (`3*Talk(+7) + 1*Eat(+2) + 1*Scratch(−12) = 21`, starting from `r15d=10`) pins it to exactly `21` regardless of what you type (as long as the 32-character length constraint is satisfied so the gate is even reached).

#### Step 4 — Solve offline

`scripts/solve_cat.py` reimplements the hash + keystream loop in Python and runs it directly against the ciphertext pulled from `.rodata`, with `r15d` hardcoded to `21`:

```
$ python scripts/solve_cat.py
ciphertext: 24509693cf564e7aa761d40e2415a3e389be4c
FLAG: bronco{fluffy_baby}
```

No need to actually play the game and hit the length-32 constraint by hand — the flag is fully deterministic once `r15d` is known.

### Flag

```
bronco{fluffy_baby}
```
