# Garbage In, Flag Out

> **Category**: Crypto
>
> **Flag**: `bronco{n0t_r4nd0m_3nough}`

> I've finally fixed the entropy issue with the OTPs! The secret: use them twice, but only slightly. It'll make more sense once you look at the code. … the flag (which I assure you is valid English leetspeak)…

_(Same underlying challenge as "LEts A go".)_

### Challenge

`challenge.py` + `output.txt`. One `key = random.randbytes(N)` is generated, then:

```python
garb = block_encrypt(key, real_garb)   # real_garb = 2N lowercase ascii chars
key  = scramble(key)                    # scramble = bit-reverse each byte
flag = block_encrypt(key, FLAG)         # FLAG length N
```

### Reasoning

"Use them twice, but only slightly" = **the same key is reused** for both outputs.

* **Garbage, first half:** `garb[0:N] = key XOR real_garb[0:N]`, and `real_garb` is known to be lowercase `a–z`. So each `key[i]` collapses to only **26 candidate bytes**.
* **Flag:** `flag_out[i] = scramble(key)[i] XOR FLAG[i]`, where `scramble` bit-reverses each byte. Thus `FLAG[i] = bitrev(key[i]) XOR flag_out[i]`.

Keep only candidates whose flag byte is printable (\~9 left per position). A second constraint from the garbage's **second half** (`garb[N:2N]` is the deterministic key extension XOR more lowercase garbage; the extension byte's high nibble is fixed by `key[i]`) knocks it down to 1–2 candidates per position. The English-leetspeak reading fixes the rest.

### PoC / Reproduction

```
$ python solve.py
per-position candidates:
[bR][rB]o[^n][Sc][_o][{K][^n]0[Dt][_o][Br]4[n^][Td]0[]m]_3[n^][_o][uE][gW]h[}M]
flag: bronco{n0t_r4nd0m_3nough}
```

`solve.py`, `challenge.py`, `output.txt` included.

### Tools

* Python 3 (stdlib only).

### Key Takeaway

An OTP is only as strong as its key's entropy. Reusing a key (even lightly transformed by a reversible `scramble`) plus a **known plaintext alphabet** (lowercase garbage) turns the pad into a solvable per-byte constraint problem. "Not random enough."
