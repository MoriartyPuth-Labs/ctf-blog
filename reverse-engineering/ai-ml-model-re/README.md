# AI / ML Model RE

Reversing compiled machine learning models (TensorFlow Lite, PyTorch, ONNX), weight extraction, and Decision Tree function deobfuscation.

***

### 1. Reversing Compiled ONNX / TFLite Models

Machine learning models compiled into standalone binaries or mobile assets (`.tflite`, `.onnx`, `.pb`) store neural network architectures, layer parameters, and weight matrices.

#### Inspection & Extraction Tools

* **Netron:** Visualizer for neural network models (`.onnx`, `.tflite`, `.keras`, `.pth`).
* **ONNX Python API:** Inspect nodes, tensor shapes, and layer weights programmatically:

```python
import onnx
from onnx import numpy_helper

# 1. Load ONNX Model
model = onnx.load("target_model.onnx")

# 2. Extract Initializer Weights
for tensor in model.graph.initializer:
    weights = numpy_helper.to_array(tensor)
    print(f"Layer: {tensor.name}, Shape: {weights.shape}")
```

***

### 2. Inverting Neural Network Activation Layers (Sigmoid / ReLU)

In AI CTF challenges, flags are validated through dense neural network layers:

$$\text{Output} = \text{Activation}(W \cdot X + b)$$

#### Inversion Strategy

1. Extract Weight Matrix $W$ and Bias Vector $b$.
2. Invert activation functions (e.g. $\text{Sigmoid}^{-1}(y) = \ln(y / (1 - y))$).
3. Solve linear matrix equation $W \cdot X = Y\_{\text{target\}} - b$ using **NumPy `np.linalg.solve()`** or **Z3** to recover input vector $X$ (the flag!).
