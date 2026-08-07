# Probably Unbreakable

> **Category**: Crypt
>
> **Flag**: `bronco{4t_l3a5t_1mpr0b4b1e_th0ugh}`

> I set up a place for everyone to enjoy their favorite thing: random numbers! … I even left the flag in there. … There's definitely a way to find it. Just kidding! Probably.

### Challenge

`chall.py` + a remote service (`nc 0.cloud.chals.io 16474`). You pick quantities for three operations; the useful one is "flag encryptions" (up to \~20000). Each encryption is `enc = flag XOR key` where each key char is `random.choices(keystring, k=len(flag))`:

```python
keystring = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
```

### Reasoning

The `scramble_list` / `pick_random_letters` operations are **red herrings** meant to bait a Mersenne-Twister state-recovery attack. The real flaw is much simpler:

**`keystring` is exactly 64 characters** (26 + 26 + 10 + 2). So every key byte is a uniform pick from a _known set of 64 ASCII values_. For the true flag byte `c`, `c XOR enc[i]` must be one of those 64 known key values **for every sample**. Intersect the candidate sets across thousands of encryptions and each position collapses to a single byte — no RNG prediction needed.

```
flag_byte ∈ ⋂_samples { enc_sample[i] XOR k : k ∈ keyset }
```

### PoC / Reproduction

```
$ python solve.py            # connects, requests 20000 encryptions, intersects
bronco{4t_l3a5t_1mpr0b4b1e_th0ugh}
```

`solve.py` and `chall.py` included. Live/interactive.

### Tools

* Python 3 (`socket`, stdlib).

### Key Takeaway

A one-time pad drawn from a **restricted alphabet** (here 64 known ASCII values) leaks the plaintext under multi-sample XOR analysis, regardless of how good the RNG is. Don't get lured into predicting MT19937 when the alphabet size hands you the plaintext for free — "at least improbable, though."
