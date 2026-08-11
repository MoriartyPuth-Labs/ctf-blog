# ONNX & TFLite Model Decompilation

Decompiling compiled machine learning models (`.onnx`, `.tflite`, `.keras`, `.pth`) and visualizer tooling.

***

### 1. Model Structure Inspection via Netron

Visualizing neural network graphs:

* Launch **Netron** (`netron target_model.onnx` or web UI at [netron.app](https://netron.app)).
* Inspect input/output tensor shapes, layer operations (`Conv2D`, `Dense`, `Reshape`), and parameter names.

***

### 2. Programmatic Model Inspection with ONNX Python API

```python
import onnx

model = onnx.load("target_model.onnx")

# Print Input and Output Tensor Names & Shapes
print("[+] Model Inputs:")
for input in model.graph.input:
    print(f"  Name: {input.name}, Type: {input.type.tensor_type.elem_type}")

print("[+] Model Layers / Nodes:")
for node in model.graph.node:
    print(f"  OpType: {node.op_type}, Inputs: {node.input}, Outputs: {node.output}")
```
