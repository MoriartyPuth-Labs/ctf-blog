# Blorg Multiplier

> **Category**: Crypto
>
> **Flag**: `bronco{ple4s3_d0nt_l3ak_fl4g}`

> Blorgs! Blorgs everywhere! Can you convince the Blorg Master to hand over his flag?

### Challenge

`checker.py` + a remote service (`nc 0.cloud.chals.io 13758`). A command interpreter validates every command by `md5(input) in valid`. Goal: reach `blorgs == 468` (start 1) using at most 3 "edits", where:

```
increase: blorgs = (blorgs + 1) * 2   (costs an edit)
decrease: blorgs = (blorgs - 1) * 2   (costs an edit)
none:     blorgs *= 2                 (free)
program:  register a new command name -> adds md5(name) to `valid`
```

The flag prints only in the `else` branch of `handle_input`, reached by a command that is **valid but not one of the handled names**, and only when `blorgs == 468`.

### Reasoning

**Trap 1 — `show` is deliberately dead.** `valid` stores the `show` hash in **UPPERCASE** (`A7DD12...`) while `hashlib.hexdigest()` is always lowercase, so `select == "A7DD..."` can never be true. `show` is unusable on purpose.

**Trap 2 — `program` can't self-reach `else`.** Registering name `A` sets `program = A` and adds `md5(A)`, but then calling `A` hits `elif user_in == program`, not `else`. Redefining removes the old hash, so at any moment exactly one custom hash is valid and it always equals `program`. No valid, unhandled command is reachable this way…

**…except via an MD5 collision.** Register program name `A`, then send a _different_ string `B` with `md5(B) == md5(A)`. Validity passes (`md5(B) ∈ valid`), but `B != program` (`B != A`), so it falls through every `elif` into `else` → flag.

**The blorg math** must hit exactly 468 within 3 edits while the loop stays alive (`blorgs <= 468 and edits <= 3`). Working backward: `468 = 2^9 − 2^5 − 2^3 − 2^2`, i.e. three `decrease`s among six `none`s:

```
none none none none decrease none decrease decrease none
1 -> 2 -> 4 -> 8 -> 16 -> 30 -> 60 -> 118 -> 234 -> 468   (edits = 3)
```

#### Generating the collision (HashClash fastcoll)

The 128-byte collision blocks must avoid `0x0a`/`0x0d`/`0x00` (the service reads commands line-by-line via `input()`; a newline would truncate). Build the real tool and loop with fresh seeds until both blocks are clean:

```bash
# Linux/WSL: needs gcc g++ make autoconf automake libtool libbz2-dev zlib1g-dev
git clone https://github.com/cr-marcstevens/hashclash && cd hashclash && ./build.sh
for i in $(seq 1 200); do
  ./bin/md5_fastcoll --seed1 $RANDOM$RANDOM -o m1.bin m2.bin >/dev/null 2>&1
  python3 - <<'PY' && { cp m1.bin A.bin; cp m2.bin B.bin; break; }
import sys
d1=open('m1.bin','rb').read(); d2=open('m2.bin','rb').read()
bad=(0x0a,0x0d,0x00)
sys.exit(0 if all(b not in bad for b in d1+d2) and d1!=d2 else 1)
PY
done
```

`md5_fastcoll`'s default IHV is the standard MD5 IV, so the pair collides under stdlib `hashlib.md5`. The pair embedded in `exploit.py` has `md5 = 362c60db4ecc45d9a9f232c241602b61`.

#### Encoding trick

Commands go through `input()` (UTF-8 decode) then `.encode("latin-1")`. To make the server hash the exact bytes `M`, send `M.decode("latin-1").encode("utf-8")` — the server's `input()` decodes it back to the codepoints and `.encode("latin-1")` reproduces `M` (high bytes ride as valid 2-byte UTF-8; only `0x0a`/`0x0d` would break line reading).

### PoC / Reproduction

```
$ python exploit.py
Wow! You earned the flag: bronco{ple4s3_d0nt_l3ak_fl4g}
```

`exploit.py` (collision pair embedded) and `checker.py` included.

### Tools

* Python 3 (`socket`, `hashlib`).
* **HashClash `md5_fastcoll`** — [https://github.com/cr-marcstevens/hashclash](https://github.com/cr-marcstevens/hashclash) (built on Linux/WSL) for the real identical-prefix MD5 collision.

### Key Takeaway

Authenticating commands by MD5 is fatal. `program` lets you register `md5(A)` as valid; a collision `md5(B) == md5(A)` with `B != A` then behaves as a _wildcard_ command that slips past every handled branch into `else`. The uppercase-`show` hash and the RNG-flavored blorg math are misdirection — the crux is an MD5 identical-prefix collision. "Please don't leak flag."
