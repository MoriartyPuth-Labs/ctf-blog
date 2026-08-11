# Custom Ciphers, LFSRs, & Feistel

Reversing custom encryption schemes, Linear Feedback Shift Registers (LFSR), key schedules, and multi-round Feistel structures.

***

### 1. Linear Feedback Shift Registers (LFSR)

LFSRs generate pseudo-random keystreams driven by bitwise shift and XOR feedback taps.

$$\text{Next Bit} = (s_{n-1} \cdot c_1) \oplus (s_{n-2} \cdot c_2) \oplus \dots \oplus (s_0 \cdot c_n)$$

#### Reversing LFSR

1. Identify **Tap Positions** (which bit registers are XORed).
2. Given $2N$ output keystream bits, use the **Berlekamp-Massey Algorithm** to reconstruct the feedback polynomial and initial seed state!

***

### 2. Custom Feistel Networks

A Feistel network divides input into Left ($L$) and Right ($R$) halves:

```
[ Input 64-bit Block ] ──► Split into L_0 (32-bit) and R_0 (32-bit)
                              │
  Round 1: L_1 = R_0          │ R_1 = L_0 ^ RoundFunc(R_0, Key_1)
  Round 2: L_2 = R_1          │ R_2 = L_1 ^ RoundFunc(R_1, Key_2)
                              ...
```

#### Decryption Formula

To decrypt, apply the exact same round function in reverse order (using subkeys $K\_n, K\_{n-1}, \dots, K\_1$): $$R_i = L_{i+1} \quad | \quad L_i = R_{i+1} \oplus F(L_{i+1}, K_{i+1})$$
