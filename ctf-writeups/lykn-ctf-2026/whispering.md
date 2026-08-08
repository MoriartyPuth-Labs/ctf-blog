# Whispering

> **Category**: Crypto
>
> **Flag**: `LYKNCTF{af9ccf9a4b1041a6840fa5ba9e732347}`

**Challenge**: A custom NTRU-based encryption scheme leaks the sums of the private polynomial coefficients through a side channel. Recover the algebraic signature used to derive the AES key and decrypt the flag.

***

### Table of Contents

1. Challenge Overview
2. Code Analysis
3. Vulnerability — Side-Channel Leakage
4. Exploitation
5. Reproduction
6. Tools Used
7. Lessons Learned

***

### Challenge Overview

The server exposes two endpoints:

| Endpoint                 | Content                                                       |
| ------------------------ | ------------------------------------------------------------- |
| `GET /public.json`       | NTRU parameters, public key `h`, encrypted flag (AES-256-CBC) |
| `GET /side_channel.json` | Sums of polynomial coefficients modulo 127                    |

The flag is AES-CBC encrypted with a key derived from the **algebraic signature** `V = Σ (f * g)`. If we can recover `V` we can decrypt.

***

### Code Analysis

#### NTRU Key Generation

The server generates two secret ternary polynomials `f` and `g` (coefficients in {-1, 0, 1}) with the constraint that at least `⌈N/2⌉` coefficients are non-zero.

The public key is:

```
h ≡ g * f_inv  (mod q, x^N - 1)
```

#### Algebraic Signature

The signature `V` is defined as:

```python
def compute_algebraic_signature(self):
    fg_product = self.params.poly_mult_mod(self.f, self.g, self.params.q_prime)
    trace = sum(fg_product) % self.params.q_prime
    return trace
```

Because `poly_mult_mod` computes a convolution product

```
(f * g)[k] = Σ_{i+j ≡ k (mod N)} f[i] · g[j]   (mod q_prime)
```

summing over all `k` gives every pairwise product exactly once:

```
V = Σ_k (f * g)[k] = Σ_i Σ_j f[i] · g[j] = (Σ_i f[i]) · (Σ_j g[j])
```

Therefore **V = sum\_f × sum\_g mod q\_prime**.

#### Key Derivation

```python
ikm = V.to_bytes(4, "big") + N.to_bytes(2, "big") + q.to_bytes(2, "big") + salt
key = HKDF(master=ikm, key_len=32, salt=str(N).encode("utf-8"), hashmod=SHA256)
```

If we know `V`, we can reproduce the same AES key.

***

### Vulnerability — Side-Channel Leakage

The `GET /side_channel.json` endpoint reveals four values:

```json
{
  "f_even_sum_mod_127": 122,
  "f_odd_sum_mod_127":  6,
  "g_even_sum_mod_127": 4,
  "g_odd_sum_mod_127":  124
}
```

These are the sums of every other coefficient of `f` and `g`, reduced modulo 127. Because the coefficients are in {-1, 0, 1}, the sums fall in narrow ranges:

| Variable | # coeffs | Possible range |
| -------- | -------- | -------------- |
| `f_even` | 64       | \[-64, +64]    |
| `f_odd`  | 63       | \[-63, +63]    |
| `g_even` | 64       | \[-64, +64]    |
| `g_odd`  | 63       | \[-63, +63]    |

Each range is smaller than the modulus (127), so the **actual sum is uniquely recoverable**:

* If `mod_val ≤ max_abs` → actual = `mod_val`
* Otherwise → actual = `mod_val - 127`

***

### Exploitation

#### Step 1 — Recover the exact sums

```
f_even: 122 → 122 - 127 = -5
f_odd:    6 →    6
g_even:   4 →    4
g_odd:  124 → 124 - 127 = -3
```

Therefore:

```
sum_f = -5 + 6 = +1
sum_g =  4 - 3 = +1
```

#### Step 2 — Compute V

```
V = sum_f × sum_g  (mod 2053) = 1 × 1 = 1
```

#### Step 3 — Derive the key and decrypt

Feed `V=1` into the same HKDF parameters, then AES-CBC decrypt the ciphertext.

```
key = HKDF(ikm=V||N||q||salt, key_len=32, salt="127")
flag = AES-CBC-decrypt(key, iv, ciphertext)
```

#### Result

**`LYKNCTF{af9ccf9a4b1041a6840fa5ba9e732347}`**

***

### Reproduction

```bash
# Install dependency
pip install pycryptodome requests

# Run the solve script (replace URL with your instance)
python3 solve.py http://db9c3975-d3e7-4db6-bd74-3a509bdb8605.51.79.140.18.nip.io:8080
```

The script will print the flag to stdout.

***

### Tools Used

| Tool               | Purpose                               |
| ------------------ | ------------------------------------- |
| Python 3           | Scripting                             |
| PyCryptodome       | HKDF, AES-CBC, SHA-256                |
| requests           | HTTP client for the challenge server  |
| Manual code review | Understanding the NTRU implementation |

***

### Lessons Learned

1. **Side channels matter** — even leaking sums modulo a small prime can be enough to recover the full value when the range of possible values is constrained.
2. **Convolution structure** — the algebraic signature `V = Σ (f * g)` collapses to `(Σ f) × (Σ g)` because the convolution sum over all rotation indices counts each product exactly once.
3. **NTRU lattice attacks are unnecessary here** — the side channel makes the problem a simple arithmetic recovery, not a lattice reduction.
4. **Read the whole source** — the `poly_inverse_mod` stub returning `f` (`serverr.py:83`) is a red herring for this particular exploit path; the actual inverse is computed in `compute_inverse_simple`.
