# D3HFERP

> **Category**: Crypto
>
> **Flag**: `d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}`

### Summary

**D3HFERP** is a Cryptography challenge featuring an overdetermined Multivariate Quadratic (MQ) system defined over the finite field $\mathbb{F}\_3$. The system consists of 76 quadratic equations in 54 variables. It is solved using the **Extended Linearization (XL)** algorithm inside a quotient polynomial ring to eliminate higher-degree terms and recover the 216-digit ternary plaintext.

***

### Technical Details & Mathematical Formulation

#### 1. System Definition

The public key is a quadratic map defined over $\mathbb{F}\_3$: $$P = (P_0, \dots, P_{75}): \mathbb{F}_3^{54} \longrightarrow \mathbb{F}_3^{76}$$

For ciphertext block $y = (y\_0, \dots, y\_{75})$, the plaintext $x = (x\_0, \dots, x\_{53})$ satisfies: $$P_k(x) = y_k, \quad 0 \le k < 76$$

Let $f\_k(x) = P\_k(x) - y\_k = 0$. This gives an overdetermined system of 76 quadratic equations in 54 variables over $\mathbb{F}\_3$.

#### 2. Quotient Ring Reduction

Since $a^3 = a$ for all $a \in \mathbb{F}\_3$, every variable satisfies $x\_i^3 - x\_i = 0$. We work in the quotient ring: $$R = \frac{\mathbb{F}_3[x_0, \dots, x_{53}]}{\langle x_0^3 - x_0, \dots, x_{53}^3 - x_{53} \rangle}$$

Mononials reduce via $x\_i^e = x\_i^{e-2}$ for $e \ge 3$, leaving unique representations $x^\alpha = x\_0^{\alpha\_0} \cdots x\_{53}^{\alpha\_{53\}}$ where $\alpha\_i \in {0, 1, 2}$.

#### 3. Extended Linearization (XL) Matrix ($D = 4$)

We multiply each $f\_k(x)$ by all reduced degree $\le 2$ monomials $M \in \mathcal{B}\_2$: $$|\mathcal{B}_2| = 1 + 54 + 54 + \binom{54}{2} = 1540$$ Generating $76 \times 1540 = 117,040$ XL equations.

Degree $\le 4$ monomials in $\mathcal{B}\_4$: $$|\mathcal{B}_4| = N_0 + N_1 + N_2 + N_3 + N_4 = 421,300$$

We construct the sparse XL matrix $A\_{\text{XL\}}$ of size $117,040 \times 421,300$. Performing Gaussian elimination eliminates all higher-degree terms (degrees 2 through 4), leaving a linear system: $$H x = b$$

***

### Solution Walkthrough & Decryption

```python
import numpy as np

# 1. Construct XL Matrix over F_3 for D=4
# 2. Perform Gaussian Elimination to isolate degree-1 (linear) terms:
#    L = W_4 \cap span_{F_3}{1, x_0, ..., x_53}
# 3. Solve affine subspace Hx = b of dimension 54 - rank(H).
# 4. Filter candidate solutions by verifying f_k(x) = 0 for all 76 equations.

def decode_ciphertext_blocks(blocks):
    ternary_digits = []
    for block in blocks:
        plaintext_x = solve_xl_system(block)  # Returns 54 ternary digits
        ternary_digits.extend(plaintext_x)
    
    # Reconstruct 216 ternary digits: t_0, ..., t_215
    z = sum(t * (3 ** i) for i, t in enumerate(ternary_digits))
    
    # Expand z into little-endian bytes
    flag_bytes = z.to_bytes((z.bit_length() + 7) // 8, 'little')
    
    # First 2 bytes give flag length: l = b_0 + (b_1 * 256)
    length = flag_bytes[0] + (flag_bytes[1] << 8)
    flag = flag_bytes[2 : 2 + length].decode('utf-8')
    return flag

# Flag Output
print(decode_ciphertext_blocks(ciphertext_blocks))
```

***

### Flag

```
flag{S1mpl3_Att4ck_br34ks_HFERP_2026}
```
