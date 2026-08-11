# Weight Extraction & Layer Inversion

Extracting weight matrices, bias vectors, and inverting activation functions in deep neural networks.

***

### 1. Extracting Weights and Biases from ONNX / TFLite

```python
import onnx
from onnx import numpy_helper

model = onnx.load("target_model.onnx")
weights_dict = {}

for initializer in model.graph.initializer:
    W = numpy_helper.to_array(initializer)
    weights_dict[initializer.name] = W
    print(f"[+] Layer Weight Loaded: {initializer.name} (Shape: {W.shape})")
```

***

### 2. Inverting Dense Layers & Activation Functions

A single Dense Layer evaluates: $Y = \text{Activation}(W \cdot X + B)$

#### Inverting ReLU / Sigmoid Activation

* **Sigmoid Inversion:** $Z = \ln\left(\frac{Y}{1 - Y}\right)$
* **Linear Layer Inversion:** Solve $W \cdot X = Z - B$ using NumPy linear algebra solver:

```python
import numpy as np

# Solve W * X = Z for input vector X
W = weights_dict['dense_weight']
B = weights_dict['dense_bias']
Z = np.log(Y_target / (1 - Y_target)) - B

# Calculate input vector X
X_recovered = np.linalg.solve(W, Z)
flag = "".join([chr(int(round(val))) for val in X_recovered])
print(f"[+] Recovered Input (Flag): {flag}")
```
