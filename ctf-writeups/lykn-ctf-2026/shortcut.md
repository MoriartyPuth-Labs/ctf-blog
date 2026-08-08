# Shortcut

> **Category:** Cryptography\
> **Flag:** `LYKNCTF{95ce56e3bed44d16ba37ad2b839e984f}`

> Everyone likes shortcuts, including hastily built encryption systems built to meet deadlines. Sometimes the shortest path is the easiest to fall into a trap.

A custom RSA-based encryption scheme is used to protect the flag. The server provides:

* RSA public parameters `(N, e)`
* An AES-GCM encrypted flag with its nonce and tag
* Three "leakage" values intended to help recover private material

The challenge title and hint strongly suggest the vulnerability is fundamental and does not require sophisticated cryptanalysis.

***

### Source Code Analysis

The server runs `gen_params.py`, which does the following:

#### 1. RSA Key Generation (Small `d`)

```python
d_target_bits = int(bits * 0.205)          # d ≈ 315 bits for 1536-bit N
d = getPrime(d_target_bits)
wiener_bound = isqrt(isqrt(N)) // 3         # N^0.25 / 3
if d >= wiener_bound:                       # keep regenerating until d is small enough
    continue
```

The code **explicitly enforces** `d < N^0.25 / 3` — the exact condition for Wiener's continued-fraction attack. This is the primary vulnerability.

#### 2. Leakages (Red Herrings?)

Three leakages are provided:

| Leakage          | What it leaks                    |
| ---------------- | -------------------------------- |
| `R1, M1`         | `p-1 ≡ R1 (mod M1)`              |
| `R2, M2`         | `q-1 ≡ R2 (mod M2)`              |
| `S`              | `gcd(p+q, small_value)`          |
| `lambda_mod, M3` | `lambda_n ≡ lambda_mod (mod M3)` |

These leakages are **not needed** for the simplest solve path. They exist to distract or to provide a fallback if the straightforward approach is missed.

#### 3. AES Key Derivation

```python
V_int   = long_to_bytes(d)[:16]
H1      = sha256(V_int)
H2      = sha256(long_to_bytes(S))
H3      = sha256(long_to_bytes(lambda_n))
IKM     = H1 + H2 + H3
aes_key = HKDF(sha256, length=32, salt=b"FastLane-RSA-2024", info=b"FastLane-AES-Key").derive(IKM)
```

The AES-GCM key depends on `d`, `S`, and `lambda_n`. Once Wiener's attack recovers `d` and factors `N`, all three are computable.

***

### Vulnerability — Wiener's Attack

Wiener's attack (1990) applies when the private exponent `d` satisfies:

```
d < N^0.25 / 3
```

Given `e * d ≡ 1 (mod phi(N))`, there exists `k` such that:

```
e * d - k * phi(N) = 1
```

Since `phi(N) ≈ N`, we have `e/N ≈ k/d`. Because both `k` and `d` are small (relative to N), `k/d` appears as a convergent in the continued fraction expansion of `e/N`. Testing each convergent yields the secret `d`.

***

### Solution Steps

1. **Collect parameters** from the server (`N`, `e`, `encrypted_flag`, `nonce`, `tag`, leakages)
2. **Run Wiener's attack** — compute continued fractions of `e/N`, iterate convergents until one produces valid RSA primes
3. **Factor N** using the recovered `d` (or directly use the relation `e*d ≡ 1 (mod phi)` to solve for `p`, `q`)
4. **Compute `lambda_n`** and **derive the AES key** following the same derivation as the server
5. **Decrypt AES-GCM** using the nonce, ciphertext, and tag

#### Attack Script

```python
import json
import hashlib
from math import gcd, isqrt
from Crypto.Util.number import long_to_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Load data
data = json.load(open("params.json"))
N, e = int(data["N"]), int(data["e"])
ct = bytes.fromhex(data["encrypted_flag"])
nonce = bytes.fromhex(data["nonce"])
tag = bytes.fromhex(data["tag"])
S = int(data["leakage2"]["S"])

# --- Wiener's attack ---
def continued_fraction(num, den):
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf

def convergents(cf):
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for a in cf:
        n2 = a * n1 + n0
        d2 = a * d1 + d0
        yield n2, d2
        n0, n1 = n1, n2
        d0, d1 = d1, d2

cf = continued_fraction(e, N)
for k, d in convergents(cf):
    if k == 0:
        continue
    phi_candidate = (e * d - 1) // k
    s = N - phi_candidate + 1  # p + q
    disc = s * s - 4 * N
    if disc > 0:
        t = isqrt(disc)
        if t * t == disc:
            p = (s + t) // 2
            q = (s - t) // 2
            if p * q == N:
                break
else:
    print("Wiener attack failed")
    exit(1)

print(f"[+] d = {d}")

# Derive AES key
lambda_n = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
d_bytes = long_to_bytes(d)
V_int = d_bytes[:16]
H1 = hashlib.sha256(V_int).digest()
H2 = hashlib.sha256(long_to_bytes(S)).digest()
H3 = hashlib.sha256(long_to_bytes(lambda_n)).digest()
IKM = H1 + H2 + H3

hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
            salt=b"FastLane-RSA-2024", info=b"FastLane-AES-Key")
aes_key = hkdf.derive(IKM)

# Decrypt
flag = AESGCM(aes_key).decrypt(nonce, ct + tag, None)
print(f"[+] FLAG: {flag.decode()}")
```

#### Output

```
[+] d = 25044949967447364321285713301673960792238611756004254741962076924985769597564859208659311424249
[+] AES key: 02e02c15663a4fbf21f36690a0c6688e0201fa9a75cfbfa7f7c0763808952e24
[+] FLAG: LYKNCTF{95ce56e3bed44d16ba37ad2b839e984f}
```

***

### Tools Used

| Tool           | Purpose                                                  |
| -------------- | -------------------------------------------------------- |
| Python 3       | Scripting the attack                                     |
| PyCryptodome   | RSA/prime utilities (`long_to_bytes`, `bytes_to_long`)   |
| `cryptography` | `AESGCM`, `HKDF` for deriving the AES key and decrypting |
| Netcat (`nc`)  | Connecting to the challenge server                       |

***

### Key Takeaways

1. **Wiener's attack is the first thing to check** when given an RSA public key with a suspiciously large `e` (same bit-length as `N`). A large `e` often implies small `d`.
2. **Don't overthink.** The challenge explicitly says "beginner CTF" and "simplest bugs." Despite three nontrivial-looking leakages, they were unnecessary — the classic Wiener attack sufficed.
3. **The leakages served as camouflage.** Engineers designing a "custom" cryptosystem often add complexity that looks important but is irrelevant to the simplest break.
4. **Always test the simplest exploit path first** before pursuing lattice attacks, Coppersmith, or other advanced techniques.
