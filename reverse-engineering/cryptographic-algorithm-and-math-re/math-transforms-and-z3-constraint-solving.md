# Math Transforms & Z3 Constraint Solving

Reversing Burrows-Wheeler Transform (BWT), Sprague-Grundy game states, and solving non-bijective matrix equations via Z3.

***

### 1. Burrows-Wheeler Transform (BWT) Inversion

BWT rearranges a character string into runs of similar characters.

#### Inversion Algorithm

Given transformed string $L$ and index $I$:

1. Sort string $L$ alphabetically to get first column $F$.
2. Compute **LF-mapping** vector: `LF[i]` maps position in $F$ to position in $L$.
3. Follow LF vector starting at index $I$ to reconstruct original string!

***

### 2. GF(2^8) Matrix System Solving via Z3

```python
from z3 import *

# Solve system of GF(2) XOR linear equations
x = [BitVec(f'x_{i}', 8) for i in range(4)]
s = Solver()

s.add(x[0] ^ x[1] ^ x[2] == 0x42)
s.add(x[1] ^ x[3] == 0x90)
s.add(x[0] ^ x[3] == 0x12)
s.add(x[2] ^ x[3] == 0x7f)

if s.check() == sat:
    m = s.model()
    print("Solved Variables:", [m[v].as_long() for v in x])
```
