# The Alchemist's Lock

> **Category:** Reverse Engineering
>
> **Difficulty:** Easy - Medium
>
> **Goal:** Find Flag

A technical walkthrough for solving the "Alchemist's Lock" reverse engineering challenge. This repository details the process of unpacking, analyzing a custom hashing algorithm, and ultimately bypassing the lock via binary patching.

***

### Tools Used

* **Detect-It-Easy:** For initial file analysis and packer identification.
* **x64dbg (with Scylla):** For dynamic analysis, finding the OEP, and dumping the unpacked process.
* **IDA Pro:** For static analysis and reconstructing the internal logic.

***

### Technical Analysis

#### 1. Unpacking

The binary was identified as packed using **Detect-It-Easy**. Using **x64dbg**, the Original Entry Point (OEP) was located at `00007FF76ACC1D47`. The process was then dumped using the **Scylla** plugin to allow for static analysis of the underlying code.

#### 2. Logic Flow

The core of the challenge involves a name and password validation system:

* **Input:** The program prompts for a "name" and a "password".
* **The "Magic" Function:** A call to `7FF756B117DC` processes these inputs to generate a 64-bit value.
* **Validation:** This value is compared against a magic constant: `52E85B18B8EFE7A6`.
* **Decryption:** If they match, the result is used as an XOR key to decrypt and print the flag. If they do not match, the flag remains corrupted.

#### 3. Algorithmic Reconstruction

The hashing logic at `7FF756B117DC` was reconstructed into Python for verification:

```python
def rol(x, k):
    k %= 64
    return ((x << k) | (x >> (64 - k))) & 0xFFFFFFFFFFFFFFFF

def compute_magic(name, password):
    acc = 0
    res = 0
    for s in (name, password):
        L = len(s)
        for _ in range(L):
            for c in s:
                acc = (acc + ord(c)) & 0xFFFFFFFFFFFFFFFF
            acc = rol(acc, 15)
            acc = (acc * 139) & 0xFFFFFFFFFFFFFFFF
            acc = (acc >> 2) + 4
            acc &= 0xFFFFFFFFFFFFFFFF
            res = (res + acc) & 0xFFFFFFFFFFFFFFFF
    return res
```

***

#### Solution: Binary Patching

Due to the non-invertible nature of the hashing function, brute-forcing proved inefficient. The challenge was solved by patching the conditional jump responsible for the success branch:

* Original: `jz short loc_7FF76ACC22F7` (Jump if zero/equal)
* Patch: `jnz short loc_7FF76ACC22F7` (Jump if not zero/not equal)

This modification forces the program to execute the flag-printing logic regardless of the input provided.

Flag: `FLAG_R3v3rs3d`
