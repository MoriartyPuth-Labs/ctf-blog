# Cryptographic Algorithm & Math RE

Reversing custom ciphers, identifying standard cryptographic constants, recovering S-boxes, key schedules, and mathematical transforms.

***

### 1. Identifying Standard Crypto Constants in Binaries

When reversing stripped binaries, look for hardcoded mathematical constants to identify encryption algorithms instantly:

| Cryptographic Algorithm | Signature Constants               | Hex Lookup                                        |
| ----------------------- | --------------------------------- | ------------------------------------------------- |
| **AES (Rijndael)**      | AES S-Box array                   | `63 7c 77 7b f2 6b 6f c5 30 01 67 2b...`          |
| **SHA-256**             | Initial Hash Values (H0-H7)       | `6a09e667 bb67ae85 3c6ef372 a54ff53a...`          |
| **MD5**                 | Initial Constants                 | `01234567 89abcdef fedcba98 76543210`             |
| **ChaCha20 / Salsa20**  | Magic String `"expand 32-byte k"` | `65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b` |
| **CRC32**               | Polynomial table                  | `0xedb88320` or `0x04c11db7`                      |

#### Automated Identification Tools

* **FindCrypt (Ghidra / IDA Plugin):** Scans binary memory for cryptographic constants.
* **KANALL (PEiD plugin):** Scans PE files for crypto signatures.

***

### 2. Reversing Custom XOR / Feistel / Substitution Ciphers

#### 2.1 Character-by-Character Index XOR

A common CTF pattern layers repeating XOR keys with index offsets:

$$\text{Cipher}[i] = \text{Flag}[i] \oplus \text{Key}[i \pmod k] \oplus i$$

```python
# Reversing Index-based XOR Cipher in Python
def decrypt(ciphertext, key):
    plaintext = []
    for i, c in enumerate(ciphertext):
        pt_char = c ^ ord(key[i % len(key)]) ^ (i & 0xff)
        plaintext.append(chr(pt_char))
    return "".join(plaintext)
```

#### 2.2 Reversing Feistel Structure

A Feistel cipher splits data into Left ($L$) and Right ($R$) halves: $$L_{i+1} = R_i \quad | \quad R_{i+1} = L_i \oplus F(R_i, K_i)$$

To reverse: process rounds in exact reverse order using identical round keys ($K\_i$).

***

### 3. Mathematical Transforms (BWT & Matrix Elimination)

* **Burrows-Wheeler Transform (BWT):** Invert BWT using the standard Last-to-First (LF) mapping vector.
* **Linear Matrix Systems (GF(2^8)):** Express bitwise XOR linear equations as GF(2) matrices and solve using **Gaussian Elimination** or Z3!
