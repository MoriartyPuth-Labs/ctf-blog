# Custom Cipher

> **Category: Crypto**
>
> **Flag**: `bronco{f4ct0r1ng_i5_fr3e???}`

> I've finally made the perfect public-key encryption algorithm! Its security is rivaled only by its message-space efficiency. … I'll send you the flag along with my public key, and there's nothing you can do to read it.

### Challenge

`pscheme.py` + `enc.txt`. The "public key" is a monic polynomial whose roots are the private numbers:

```
pub(x) = Π (x - priv_i)
```

To encrypt a 4-char block it multiplies `pub` by `Π (x - m_j)` for the message chars, then packs the sort permutation of the block into an integer `order`.

### Reasoning

The ciphertext polynomial is literally `pub(x) · Π (x - m_j)`. Since the public key is handed to you, **divide the ciphertext polynomial by the public-key polynomial** — the private roots cancel exactly (zero remainder), leaving a degree-4 monic polynomial whose roots are the message bytes.

1. Reconstruct both polynomials (append the implicit monic leading `1`).
2. Exact integer polynomial long division: `cipher / pub` → degree-4 quotient.
3. Find its roots by testing integers `0..255` (`0` = padding).
4. Un-permute with `order`: each sorted-root's original index is packed into 2-bit slots, `idx = (order >> 2i) & 3`.

No private key, no factoring of anything hard — just division.

### PoC / Reproduction

```
$ python solve.py            # reads enc.txt from this folder
bronco{f4ct0r1ng_i5_fr3e???}
```

`solve.py`, `pscheme.py`, `enc.txt` included.

### Tools

* Python 3 (stdlib only — bignum polynomial division + brute-force root search).

### Key Takeaway

A "public key" that leaks its structure (product-of-roots) gives up the whole plaintext: the ciphertext is `pub · Π(x−mⱼ)`, so dividing out the known `pub` exposes the message poly. Security cannot rest on nobody noticing that polynomial division is free.
