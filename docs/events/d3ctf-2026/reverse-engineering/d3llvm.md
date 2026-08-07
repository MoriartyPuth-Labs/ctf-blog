# d3llvm

**Event**: `D3Ctf 2026` | **Category**: `Reverse Engineering`

---

# d3llvm

## Summary

**d3llvm** is an Android Reverse Engineering challenge featuring an OLLVM-obfuscated shared library (`libd3llvm_payload.so`). The application verifies a 64-character handwritten authentication token using a local MNN machine learning model. Once the token is verified through a custom 16-bit non-linear mixing network, `nativeRevealFlag` decrypts the flag using AES-128-ECB.

---

## Technical Details & Architecture Analysis

1. **Native Libraries**:
   - `libd3llvm.so`: Responsible for environment checks, code-signature verification, dex integrity checks, and payload decryption.
   - `libd3llvm_payload.so`: Contains OLLVM control-flow flattening. Houses the core token verification algorithm and flag decryption functions.

2. **Bypassing Environment Integrity Checks**:
   Detection logic resides in `sub_103BC` in `libd3llvm.so`. Memory dumping `libd3llvm_payload.so` after runtime initialization bypasses inline hook checks and `Payload_OnLoad` signature verification.

3. **JNI Method Table & Verification Algorithm**:
   In `libd3llvm_payload.so`, locating `JNIMethod_table` leads to `nativeVerifyInput` (`sub_35330`).
   - Accepts a 64-character hex string representing 16 16-bit unsigned words ($w_0, \dots, w_{15}$).
   - Validates input words through 16-bit non-linear mixing functions (`mix3`, `mix4`, `cross`) against row, column, diagonal, and 32-bit rolling hash constraints (`sub_34F64`).

4. **Flag Decryption (`sub_2F7CC`)**:
   After `nativeVerifyInput` succeeds, `sub_2F7CC` derives an AES-128 key from the 64-bit FNV-1a hash of the input token and a global secret `qword_431C8 = 0xa01c8100444fb480`:
   ```python
   token_hash = fnv1a64(token_text)
   first  = mix_key_word(token_hash ^ qword_431C8 ^ 0xD3C7F19A5EED2026)
   second = mix_key_word(qword_431C8 ^ rol64(token_hash, 17) ^ 0xA11CE5C0DEC0DE42)
   aes_key = first.to_bytes(8, 'little') + second.to_bytes(8, 'little')
   ```

---

## Walkthrough & Solver Script

We solve the 16-bit mixing constraint system in Python to recover the exact 64-character token (`KNOWN_HEX`), then derive the AES key and decrypt `ENCRYPTED_FLAG`:

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES

MASK16 = 0xFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

ENCRYPTED_FLAG = bytes([
    0xF1, 0x54, 0xEA, 0xEA, 0xFA, 0xEB, 0xF0, 0x16, 0x74, 0xF0, 0x62, 0x26,
    0x70, 0x87, 0xE5, 0x84, 0xF3, 0x84, 0x2F, 0x34, 0x2F, 0x59, 0x28, 0x3D,
    0xBF, 0x51, 0x5A, 0xAC, 0xF4, 0xCD, 0x01, 0xD1, 0x51, 0xC2, 0xA5, 0x02,
    0xB3, 0x6D, 0x45, 0xBE, 0x5C, 0xB5, 0xF9, 0xB1, 0x19, 0x42, 0xD2, 0xC1,
])

qword_431C8 = 0xa01c8100444fb480

def fnv1a64(text: str) -> int:
    h = 0xCBF29CE484222325
    for b in text.encode():
        h ^= b
        h = (h * 0x100000001B3) & MASK64
    return h

def mix_key_word(val: int) -> int:
    val = (val + 0x9E3779B97F4A7C15) & MASK64
    val = ((val ^ (val >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    val = ((val ^ (val >> 27)) * 0x94D049BB133111EB) & MASK64
    return (val ^ (val >> 31)) & MASK64

def rol64(val: int, shift: int) -> int:
    shift &= 63
    return ((val << shift) | (val >> (64 - shift))) & MASK64

def decrypt_flag(token: str) -> str:
    token_hash = fnv1a64(token)
    first = mix_key_word(token_hash ^ qword_431C8 ^ 0xD3C7F19A5EED2026)
    second = mix_key_word(qword_431C8 ^ rol64(token_hash, 17) ^ 0xA11CE5C0DEC0DE42)
    key = first.to_bytes(8, "little") + second.to_bytes(8, "little")
    
    cipher = AES.new(key, AES.MODE_ECB)
    plain = cipher.decrypt(ENCRYPTED_FLAG)
    pad = plain[-1]
    return plain[:-pad].decode("ascii")

# Solved 64-character input token from constraint solver
token = "196f0d201332b47deb98221f33c7f4a13d03de6c2a77279c4dbc1f87e4d297a8"
print(f"Flag: {decrypt_flag(token)}")
```

---

## Flag

```
d3ctf{Hey5h4d0ww4lk3R-1d2efadd-aaef-zenu-s100}
```
