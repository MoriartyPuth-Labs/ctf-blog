# Twelve Steps

> **Category**: Crypto
>
> **Flag**: `LYKNCTF{870c2a99e1aa4386b693b9fe4139a939}`

**Challenge**: Given 12 consecutive outputs from a secret LCG, predict `out[12]`.

```
s_{n+1} = (a * s_n + c) mod m
(a, c, m, seed all secret)
```

***

### Solution

#### Concept

Linear Congruential Generators are **linear**. With enough consecutive outputs we can recover the modulus `m`, then the multiplier `a` and increment `c`.

#### Step 1 — Recover the modulus `m`

Let `t_n = s_{n+1} - s_n`. Since `s_{n+1} = a·s_n + c (mod m)`:

```
t_{n+1} ≡ a·t_n (mod m)
```

From this we derive:

```
t_{n+1}·t_{n-1} - t_n² ≡ 0 (mod m)
```

So `m` divides `t_{n+1}·t_{n-1} - t_n²` for every `n`. Compute several such values and take their GCD to recover `m`.

#### Step 2 — Recover `a` and `c`

```
a ≡ t_1 · t_0^{-1} (mod m)
c ≡ s_1 - a·s_0 (mod m)
```

#### Step 3 — Predict out\[12]

```
out[12] = (a * out[11] + c) mod m
```

***

### Solve Script

```python
import socket
import re
import math

def solve_lcg(outs):
    ts = [outs[i+1] - outs[i] for i in range(len(outs)-1)]
    vals = []
    for i in range(1, len(ts)-1):
        v = ts[i+1] * ts[i-1] - ts[i] * ts[i]
        vals.append(abs(v))
    m = vals[0]
    for v in vals[1:]:
        m = math.gcd(m, v)
    m = abs(m)
    a = (ts[1] * pow(ts[0], -1, m)) % m
    c = (outs[1] - a * outs[0]) % m
    for i in range(len(outs)-1):
        assert (a * outs[i] + c) % m == outs[i+1]
    return (a * outs[-1] + c) % m

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("51.79.140.18", 19557))
data = b""
while b"out[12]" not in data:
    data += s.recv(4096)
text = data.decode()
nums = [int(x) for x in re.findall(r'out\[\d+\] = (\d+)', text)]
pred = solve_lcg(nums)
s.sendall(f"{pred}\n".encode())
print(s.recv(4096).decode())
s.close()
```

***

### Tools Used

| Tool            | Purpose                               |
| --------------- | ------------------------------------- |
| Python 3        | Socket programming, LCG recovery math |
| `math.gcd()`    | Compute GCD to recover modulus        |
| `pow(x, -1, m)` | Modular inverse (Python 3.8+)         |

***

### Flag

```
LYKNCTF{870c2a99e1aa4386b693b9fe4139a939}
```
