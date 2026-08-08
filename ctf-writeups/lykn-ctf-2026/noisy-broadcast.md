# Noisy Broadcast

> **Category**: Crypto
>
> **Flag**: `LYKNCTF{n01sy_CRT_w1th_K4nn4n_3mb3dd1ng}`

> The same secret message was broadcast to three different recipients. Unfortunately, the communication channel was noisy — each recipient received a random ciphertext. Can you recover the original plaintext?

**Given:** `e = 3`, three RSA moduli `(n1, n2, n3)`, and three ciphertexts `(c1, c2, c3)`.

### TL;DR

The three "ciphertexts" are not actual RSA ciphertexts (`m^e mod n`). They are **three noisy copies of `m^3`** — bit-level noise was added to the same integer during broadcast. Because we have three independent copies, **bit-wise majority voting** recovers the exact `m^3`. Taking the integer cube root and converting to bytes yields the flag.

***

### Initial Analysis

#### The Data

```
e  = 3

n1 = 85228226732724847418067455743651142740476746995496551792634288054845497526120574520236279086740384492847733992149243642754289284545794328756970055580180294263535347412397459623691770532411325493069012460763918948201718038800689837937367866477998560124253040344625160586858409297252280344867998951473281810743
c1 = 258513173341110907855004634578328776675613337727374937778021308566776511394028586169719647601517686407530370600703671047834514223488817495300633613007122903215194800830817082508335094056353114537752319982589386027924378028160153097890317313131416661071211651623002925590879169419712047717

n2 = 97924666516843498160783101526130849604538813870081628922966609409449321121847131831281164670048951543379388432910134367882183266056444104250973101721344279684158309956009160730977339135393546720115388599622212761223476162768735295507584925036626029099233722497358026365940231114743083815647181152118332887931
c2 = 258513173341110907855004634578328776675613337727374937778021308566776511394028586169719647601517686407530370600703671047834514223488817495300633613007122903215194800830817082508335094056353114537752319982589386027924378028160153097890317313131416661071211651623002925590874661422038166117

n3 = 103096857448251887075257488004365940130545594057545157206836240630382407265637562317282373470695808990568775619043712493052636484505313305983891665885277023257298661110365836476991553181927650311887693236012437409897450200217448177064588660793633185238057210041784341180033593395853297481864041793470140461977
c3 = 258513173341110907855004634578328776675613337727374937778021308566776511394028586169719647601517686407530370600703671047834514223488817495300633613007122903215194800830817082508335094056353114537752319982589386027924378028160153097890317313131416661071211651623002925295726760640731851365
```

#### Observations

1. `e = 3` — small public exponent.
2. Three different moduli `n1, n2, n3` — pointing toward **Hastad's Broadcast Attack**.
3. The three ciphertexts are **remarkably similar**:

```
c1 length: 288 digits
c2 length: 288 digits
c3 length: 288 digits
Common prefix: 267 digits
```

They share **267 out of 288 decimal digits** — an impossible coincidence for random RSA ciphertexts under different moduli. The only differences are in the last 21 digits.

#### The Red Herring

Standard Hastad's attack uses the Chinese Remainder Theorem (CRT):

```
CRT(c1, c2, c3  over  n1, n2, n3)  →  m^3
```

However, the CRT result was **not a perfect cube**:

```
CRT result: 3066 bits
Is perfect cube: False
```

This rules out standard Hastad's. The ciphertexts are **not** `m^3 mod n_i`.

***

### The Actual Solution

#### Step 1: Recognise the structure

The three values are independent noisy transmissions of the **same integer** (the true `m^3`). The "noisy channel" introduced random bit-level errors. With three copies, we can reconstruct the original via **majority voting**.

#### Step 2: Bit-wise majority

Convert each `c_i` to its binary representation, pad to equal length, and for each bit position take the value that appears in at least 2 of the 3 copies:

```python
b1 = bin(c1)[2:].zfill(max_bits)
b2 = bin(c2)[2:].zfill(max_bits)
b3 = bin(c3)[2:].zfill(max_bits)

maj_bits = ''
for i in range(max_bits):
    ones = sum(int(b1[i]), int(b2[i]), int(b3[i]))
    maj_bits += '1' if ones >= 2 else '0'

c_maj = int(maj_bits, 2)
```

#### Step 3: Cube root and decode

The majority result is a **perfect cube**:

```python
from gmpy2 import iroot

root, exact = iroot(c_maj, 3)
# exact == True

flag = root.to_bytes((root.bit_length() + 7) // 8, 'big')
print(flag.decode())
```

**Flag:** `LYKNCTF{n01sy_CRT_w1th_K4nn4n_3mb3dd1ng}`

***

### Why This Works

The "ciphertexts" are not standard RSA. Instead:

1. The broadcaster computed `M = m^3` (the integer cube of the secret message).
2. The noisy channel transmitted `M` three times with small independent bit errors.
3. Each recipient received `c_i = M ⊕ noise_i` (bit flips).
4. With three independent noisy copies, majority voting corrects all errors.
5. The moduli `n1, n2, n3` and `e=3` are **misdirection** — they hint at Hastad's broadcast but are not actually needed.

The flag references **Kannan Embedding** — the lattice technique behind Coppersmith's method (used in variants of Hastad's with padding). While the simple bit-majority suffices here, the challenge alludes to the deeper connection between noisy CRT problems and lattice-based attacks.

***

### Files

| File         | Description                                |
| ------------ | ------------------------------------------ |
| `README.md`  | This writeup                               |
| `solve.py`   | Proof-of-concept solution script           |
| `output.txt` | Challenge data (e, n1, c1, n2, c2, n3, c3) |

***

### Reproduction

```bash
pip install gmpy2
python solve.py
# LYKNCTF{n01sy_CRT_w1th_K4nn4n_3mb3dd1ng}
```
