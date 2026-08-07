# Consistently Static Psuedo Random Number Generator

> **Category**: Crypto
>
> **Flag**: `bronco{crypt0_1n5ecur3_4_c3rt4in}`

> I made a birthday oracle recently, but I can't get it to work at all. It only gets the day of the week right 14% of the time! Here are my results from the last testing session…

### Challenge

`challenge.py` + `results.txt`. A custom PRNG is seeded with the **flag bytes** and drives a "birthday oracle". Each guess prints `month = guess%12`, `day = guess%7`, `area = guess%5`.

```python
def next(self):
    a = sum(self.state) % 256
    self.state[self.schedule[self.nextrep % len(self.schedule)]] = a
    self.nextrep += 1
    return a
```

`schedule` is `range(N)` rotated by an unknown `shift` and optionally reversed.

### Reasoning

Three ideas combine:

1. **CRT byte recovery.** `lcm(12,7,5) = 420 > 256`, so `(guess%12, guess%7, guess%5)` uniquely identifies `guess ∈ [0,256)`. Every "wrong" oracle line therefore leaks an exact PRNG output byte `a_i`.
2. **The PRNG is linear / invertible.** `next()` sets `a = sum(state) % 256` then overwrites one slot with `a`, so `sum(state_after) = 2·a_i − old_value (mod 256)`, giving `old_value = (2·a_i − a_{i+1}) mod 256`. During the **first pass** over `schedule`, each overwritten slot still holds an original **flag byte** — so consecutive output pairs leak flag bytes directly, permuted only by `schedule`.
3. **Brute the schedule.** Try every `shift` (0..N) and the `reverse` bit (\~2N total), reassemble, and read the printable `bronco{...}`. The true flag has a trailing `\n` (file read in binary), so `N = 34`.

### PoC / Reproduction

```
$ python solve.py            # reads results.txt from this folder
recovered 101 PRNG output bytes
flag: bronco{crypt0_1n5ecur3_4_c3rt4in}
```

`solve.py`, `challenge.py`, `results.txt` included.

### Tools

* Python 3 (stdlib only).

### Key Takeaway

Seeding a PRNG with your secret and exposing its outputs (even mod small numbers) is fatal when the update is **linear and invertible**: `old = 2·a_i − a_{i+1}` peels the seed straight back out. The mod-12/7/5 "lossy" outputs aren't lossy at all thanks to CRT. Crypto is insecure, for certain.
