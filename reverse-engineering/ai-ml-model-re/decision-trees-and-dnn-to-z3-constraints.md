# Decision Trees & DNN to Z3 Constraints

Converting Random Forest decision trees and deep neural network logic into Z3 constraints for input recovery.

***

### 1. Converting Decision Trees to Z3 Logic

When binaries compile Decision Tree classifiers (scikit-learn / XGBoost):

```python
from z3 import *

# Define 8-bit symbolic vector for flag bytes
input_bytes = [Real(f'x_{i}') for i in range(16)]
solver = Solver()

# Translate Decision Tree If/Else Branch Logic into Z3 Constraints
solver.add(Implies(input_bytes[0] > 65.5, input_bytes[1] < 120.5))
solver.add(Implies(input_bytes[0] <= 65.5, input_bytes[2] == 88.0))
solver.add(input_bytes[0] == 67.0) # Target class leaf constraint

if solver.check() == sat:
    m = solver.model()
    recovered_flag = "".join([chr(int(m[b].as_decimal(0))) for b in input_bytes])
    print(f"[+] Recovered Flag from Decision Tree: {recovered_flag}")
```
