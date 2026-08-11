# Standard Crypto Algorithm Identification

Identifying standard cryptographic ciphers (AES, RSA, ECC, ChaCha20, SHA-256, CRC32) via S-boxes, magic constants, and automated scanning plugins.

***

### 1. Crypto Signature Constant Table

| Cipher                | Key Constants / Signatures | Hex Signature Pattern                            |
| --------------------- | -------------------------- | ------------------------------------------------ |
| **AES S-Box**         | `0x63, 0x7c, 0x77, 0x7b`   | `63 7c 77 7b f2 6b 6f c5 30 01 67 2b...`         |
| **AES Inverse S-Box** | `0x52, 0x09, 0x6a, 0xd5`   | `52 09 6a d5 30 36 a5 38 bf 40 a3 9e...`         |
| **ChaCha20**          | Magic Constant             | `"expand 32-byte k"` (`65 78 70 61 6e 64 20...`) |
| **SHA-256**           | Initial Hash Values        | `0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a` |
| **SHA-1**             | Initial Hash Values        | `0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476` |
| **MD5**               | Initial Hash Values        | `0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210` |
| **CRC32**             | Polynomial Table           | `0xedb88320` (Reverse) or `0x04c11db7` (Normal)  |

***

### 2. Scanning Plugins

#### Ghidra / IDA FindCrypt

* **FindCrypt (Ghidra):** Install plugin $\rightarrow$ Run Analysis $\rightarrow$ Scans `.rodata` and `.data` sections for known crypto constants and flags function offsets automatically.
