# Postbox

> **Category**: Crypto
>
> **Flag**: `LYKNCTF{7bb9a077b7c947aaab1dfa5b639b5778}`

> We found a login service that issues encrypted session tokens. The server will tell us if the padding is valid. Can you recover the admin's session token and find the flag?

**Given:** A running service at a dynamic IP with three endpoints:

* `GET /` — simple status page
* `GET /login` — returns `{"iv": "<hex>", "ciphertext": "<hex>"}`
* `POST /decrypt` — accepts `{"iv": "<hex>", "ciphertext": "<hex>"}`, returns `{"ok": true}` if PKCS#7 padding is valid, `{"error": "bad padding"}` otherwise

### TL;DR

The server encrypts session data with **AES-128-CBC** and reveals a **padding oracle**: it tells us whether the decrypted plaintext has valid PKCS#7 padding. By crafting ciphertext blocks and observing the oracle, we decrypt the token byte-by-byte without knowing the key. The flag is embedded in the token.

***

### Table of Contents

1. Initial Analysis
2. The Vulnerability
3. Padding Oracle Attack Explained
4. Implementation
5. Recovering the Flag
6. Full Solution Script
7. Reproduction

***

### Initial Analysis

#### The Service

Connecting to the server reveals three endpoints:

```
GET  /        → "Postbox. A login service."
GET  /login   → {"iv": "a2d8cafad1a2978d63f63f776dba1ff2",
                  "ciphertext": "10a017c795bda354b5d6b0a375a69965..."
                  "note": "AES-128-CBC token. POST manipulated (iv, ciphertext) to /decrypt..."}
POST /decrypt → {"ok": true} or {"error": "bad padding"}
```

#### The Token

The token is 96 bytes (192 hex chars), which splits into 6 AES blocks of 16 bytes:

| Block  | Ciphertext (hex)                   |
| ------ | ---------------------------------- |
| IV     | `a2d8cafad1a2978d63f63f776dba1ff2` |
| CT\[0] | `10a017c795bda354b5d6b0a375a69965` |
| CT\[1] | `0b329323a830f821b8aae00001580b74` |
| CT\[2] | `75894bfbb36bc2b63e8607b200b9324c` |
| CT\[3] | `46a36d43fc990556cb39474f6d6a8382` |
| CT\[4] | `a2eea270d9dae2e97cc84d02d4fcdb0a` |
| CT\[5] | `1064930c62699e1b81cc8fc7680a4c21` |

#### The Oracle

The `/decrypt` endpoint attempts to decrypt the provided ciphertext with AES-128-CBC using a server-side key. If the decrypted plaintext ends with valid PKCS#7 padding, it returns `{"ok": true}`. Otherwise, it returns `{"error": "bad padding"}`.

This is a textbook **padding oracle** — the server leaks information about the decrypted plaintext through its padding validation response.

***

### The Vulnerability

**AES-CBC with PKCS#7 padding is vulnerable to padding oracle attacks** when the server reveals whether padding is valid.

In AES-CBC decryption:

```
P_i = D_k(C_i) ⊕ C_{i-1}
```

Where:

* `P_i` is plaintext block i
* `C_i` is ciphertext block i
* `D_k` is AES decryption with key k
* `C_0` is the IV

The attacker controls both the IV and the ciphertext. By modifying the ciphertext and observing the oracle, we can recover the **intermediate value** `D_k(C_i)`, and then XOR with `C_{i-1}` to get the plaintext.

***

### Padding Oracle Attack Explained

#### PKCS#7 Padding

PKCS#7 pads plaintext to a multiple of the block size (16 bytes). The last byte of the plaintext indicates how many padding bytes were added (value `0x01` through `0x10`).

For example, a 31-byte plaintext gets `0x01` as the 32nd byte. A 32-byte plaintext gets a full 16-byte padding block of `0x10`.

#### The Attack

To recover the last byte of a plaintext block:

1. Take the target ciphertext block `C_i` and a "tweak" block `T` (any 16 bytes).
2. Send `(T, C_i)` to the oracle.
3. The server decrypts `C_i` to get `I = D_k(C_i)`, then XORs with `T` to get `P' = I ⊕ T`.
4. If `P'[15]` (the last byte) is `0x01`, the oracle returns `ok=true`.
5. We vary `T[15]` from `0x00` to `0xFF` until the oracle says `ok`.
6. When `ok`, we know: `I[15] ⊕ T[15] = 0x01`, so `I[15] = T[15] ⊕ 0x01`.
7. The real plaintext byte: `P_i[15] = I[15] ⊕ C_{i-1}[15]`.

For the second-to-last byte:

1. Set `T[15]` so that `I[15] ⊕ T[15] = 0x02` (i.e., `T[15] = I[15] ⊕ 0x02`).
2. Vary `T[14]` until the oracle returns `ok` (meaning `P'[14]` = `0x02`).
3. When `ok`: `I[14] = T[14] ⊕ 0x02`, then `P_i[14] = I[14] ⊕ C_{i-1}[14]`.

Repeat for all 16 bytes, then for each ciphertext block.

***

### Implementation

#### Strategy

We attack each block independently by treating the previous block (or the IV for block 0) as the tweak vector `T`.

For each block, we iterate positions `15, 14, ..., 0`:

* For position `pos`, padding target = `16 - pos`.
* Set bytes `pos+1..15` of `T` to produce the correct padding values.
* Try all 256 values for `T[pos]` until the oracle says `ok`.
* Compute `intermediate[pos] = T[pos] ⊕ (16 - pos)`.
* Compute `plaintext[pos] = intermediate[pos] ⊕ previous_block[pos]`.

#### Optimisation

The naive approach (256 sequential requests per byte × 16 bytes × 6 blocks = 24,576 requests) is slow. We parallelise:

* For each byte, send all 256 guesses in parallel batches (40 concurrent requests).
* Run all 6 block attacks concurrently using `asyncio`.

This reduces total time from \~40 minutes to \~2-3 minutes.

#### False Positives

For the last byte of a block (`pos == 15`), the oracle response is deterministic: only the correct value produces valid `0x01` padding.

For inner bytes (`pos < 15`), there's a 1/256 chance of a false positive (a random byte happens to produce valid `N`-byte padding). In practice, we didn't encounter false positives, and the plaintext is self-validating (must be printable ASCII).

***

### Recovering the Flag

Running the attack recovers all 6 blocks:

```
Block 0: session: user=gu
Block 1: est; role=viewer
Block 2: ; flag=LYKNCTF{7
Block 3: bb9a077b7c947aaa
Block 4: b1dfa5b639b5778}
Block 5: \x10×16 (PKCS#7 padding)
```

Full plaintext (80 bytes, before padding removal):

```
session: user=guest; role=viewer; flag=LYKNCTF{7bb9a077b7c947aaab1dfa5b639b5778}
```

The flag is **different per instance** — each spawned container generates a unique random 128-bit flag value. The recovered value above is from one specific instance.

**Flag:** `LYKNCTF{7bb9a077b7c947aaab1dfa5b639b5778}`

***

### Full Solution Script

The complete solve script (`solve.py`) uses `asyncio` + `aiohttp` for parallelised padding oracle decryption:

* Fetches token from `GET /login`
* Splits into 6 blocks
* Attacks all 6 blocks concurrently
* Each block iterates bytes 15→0 with parallelised oracle queries
* Strips PKCS#7 padding and outputs the plaintext

***

### Reproduction

#### Requirements

```bash
pip install aiohttp
```

#### Running

```bash
# Set the instance URL
INSTANCE="http://<uuid>.51.79.140.18.nip.io:8080"

# Run the solve script
python solve.py "$INSTANCE"
```

#### Example Output

```
IV: a2d8cafad1a2978d63f63f776dba1ff2
CT: 10a017c795bda354b5d6b0a375a69965...4c21
6 blocks

[B0] pos 15: 0xf5 -> \xf4 [1/16] 9.9s
...
[B2] pos  0: 0x59 -> I [16/16] 2.8s
[B2] hex: 3b20666c61673d4c594b4e4354467b37  str: ; flag=LYKNCTF{7
...

=== Full (80 bytes) ===
session: user=guest; role=viewer; flag=LYKNCTF{7bb9a077b7c947aaab1dfa5b639b5778}
```

#### Files

| File                  | Description                                   |
| --------------------- | --------------------------------------------- |
| `README.md`           | This writeup                                  |
| `solve.py`            | Proof-of-concept padding oracle attack script |
| `challenge2_solve.py` | Alternative script from during the CTF        |

***

### Key Takeaways

1. **Never leak padding validity.** A padding oracle defeats AES-CBC encryption entirely.
2. **Use authenticated encryption (AEAD).** GCM or CCM modes prevent padding oracle attacks by authenticating the ciphertext.
3. **The flag is dynamic.** The challenge spawns instances with random flag values, so replaying an old flag from a different instance won't work.

***

### References

* [Padding Oracle Attack (Wikipedia)](https://en.wikipedia.org/wiki/Padding_oracle_attack)
* [PKCS#7 Padding Standard](https://datatracker.ietf.org/doc/html/rfc2315)
* [AES-CBC Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)
* [OWASP Padding Oracle](https://owasp.org/www-community/attacks/Padding_Oracle_Attack)
