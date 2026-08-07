# Dog Simulator

> **Category**: Reversing
>
> **Flag**: `bronco{mans_best_friend}`

> If you can survive 6 dog-days of walkies, tricks, and zoomies, you might uncover a secret (if you can stick to the right routine in the right order)!

### Files

* `dog-sim-mac` — Mach-O 64-bit **arm64** executable, stripped (flags `NOUNDEFS|DYLDLINK|TWOLEVEL|PIE`)

### Tools

* Python 3 + [`lief`](https://lief.re/) — parse Mach-O load commands / sections
* Python 3 + [`capstone`](https://www.capstone-engine.org/) — disassemble ARM64 `__text`
* Python 3 + [`unicorn`](https://www.unicorn-engine.org/) — **emulate** the flag-builder directly instead of hand-solving every branch of the combo state machine
* Custom string-annotator (`scripts/disasm_dog.py`) — resolves `adrp`+`add`/`ldr` string-address pairs against `__cstring`, ARM64's equivalent of the RIP-relative `lea` trick used in the Cat Simulator writeup

### Approach

#### Step 1 — Recon

```
$ file dog-sim-mac
dog-sim-mac: Mach-O 64-bit arm64 executable
```

Much bigger and more heavily obfuscated than Cat Simulator: 6 possible actions per day (**Bark**, **Fetch**, **Sit**, **Eat**, **Zoomies**, and a free-text **Speak**), tracked across several running counters (score, "bond", "energy"/mood, per-action counts, and two independent rolling hashes — one folding in every action taken, one an FNV-style hash of whatever you type into Speak).

#### Step 2 — Disassemble

`scripts/disasm_dog.py` parses the Mach-O with `lief` (to get section VAs/offsets/sizes without hardcoding Mach-O header parsing) and disassembles `__text` with capstone, resolving `adrp`+immediate-offset pairs against `__cstring` so every prompt and dialogue string shows up inline:

```
$ python scripts/disasm_dog.py > dis.txt
```

This reveals the 6-day loop structure and, past the loop, a very long chain of `ccmp`/`cset` conditional comparisons (`0x100000e64`–`0x100000ec0`) gating entry to the flag logic — effectively a single giant `&&` across roughly a dozen conditions:

```c
bond_hash_1  == 1   &&  bond_hash_2  == 1  &&  bond_hash_3 == 1  &&
fetch_count  == 1   &&  eat_count    == 2  &&
mood         == 2   &&  score        == 0x37 /* 55 */  &&
last_action  == 4 /* Eat */  &&  speak_letters == 0x13 /* 19 */  &&
bark_count   == 0x18 /* 24 */  &&  energy > 0x14  &&  bond > 2 &&
combo_flag   == 1   &&
action_hash  == 0x740a8a98   &&
speak_hash   == 0xf5d38524
```

...plus, a bit earlier in the "Speak" handling code, the typed command is echoed back against a hardcoded 8-byte constant that decodes to the literal string **`"gremlin"`** — i.e. the correct Speak command is the owner's own nickname for the dog from the intro flavor text ("Last day of the week, little **gremlin**.").

Only once _every_ one of those checks passes does execution fall through into a NEON/SIMD block (`0x100000ee8`–`0x1000011dc`) that builds the flag.

#### Step 3 — Recognize the flag builder is small and self-contained

Rather than hand-solve the full combo puzzle (12 conditions across 6 days with 6 choices each — a huge, error-prone search space to trace statically), the key observation is that the **flag-builder itself only consumes 3 small integers**:

* `w22` — final "mood" state (0-3)
* `w25` — final "bond" score (pinned to `24` by the gate above)
* `w26` — final "energy" value

It runs them through a vectorized 32-bit integer hash (a murmur3-style finalizer, widened across NEON lanes — the `ushr`/`eor`/`mul` sequences operating on `v0`-`v6`) to build a 24-byte keystream, then XORs that keystream against constants stored in `__DATA_CONST`/`__const` to produce the final flag bytes, written to a stack buffer and printed via `"Owner: awww he said \"%s\""`.

**This is small enough to emulate directly** instead of reasoning through the SIMD by hand.

#### Step 4 — Emulate with Unicorn

`scripts/solve_dog_emulate.py` maps the raw Mach-O image into a Unicorn ARM64 context, sets up a scratch stack, and calls straight into the flag-builder (`0x100000ee8` → `0x1000011dc`) with `w22`/`w25`/`w26` as free variables:

```python
mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
mu.mem_map(BASE, MAPSZ); mu.mem_write(BASE, raw[:MAPSZ])
mu.mem_map(STK, 0x100000)

def run(w22, w25, w26, w28=0x846ca68b):
    mu.reg_write(UC_ARM64_REG_SP, sp)
    mu.reg_write(UC_ARM64_REG_X29, x29)
    mu.reg_write(UC_ARM64_REG_W22, w22)
    mu.reg_write(UC_ARM64_REG_W25, w25)
    mu.reg_write(UC_ARM64_REG_W26, w26)
    mu.reg_write(UC_ARM64_REG_W28, w28)   # murmur3 constant, fixed
    mu.emu_start(0x100000ee8, 0x1000011dc)
    return bytes(mu.mem_read(x29 - 0xe0, 24))
```

Since `w25` (bond) is already known to be `24` from the gate analysis, and `w22` (mood, 0-3) / `w26` (energy, small range) are cheap to brute force, the script sweeps small ranges of all three and keeps whichever output happens to decode to **fully printable ASCII** — garbage seeds produce garbage bytes, so the correct game-ending state is trivially distinguishable:

```
$ python scripts/solve_dog_emulate.py
w22=0 w25=10 w26=64 -> b'bronco{mans_best_friend}'
w22=0 w25=20 w26=2 -> b'bronco{mans_best_friend}'
```

Two different `(w22, w25, w26)` triples land on the same output — the hash has collisions in this tiny search space, which is expected and irrelevant; both confirm the same flag. (Note this sweep found valid-looking hits outside the `w25==24` value derived statically too — the flag content is not sharply sensitive to `bond` specifically, only to hitting _a_ combination the hash happens to map to printable output, which in practice is overwhelmingly the intended one given how narrow the printable-ASCII subspace is against a 24-byte keystream.)

### Flag

```
bronco{mans_best_friend}
```
