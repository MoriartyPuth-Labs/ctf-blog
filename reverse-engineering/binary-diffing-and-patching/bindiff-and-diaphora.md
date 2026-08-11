# BinDiff & Diaphora

Performing 1-Day patch diffing analysis by comparing unpatched (vulnerable) and patched (fixed) binaries using BinDiff and Diaphora.

***

### 1. Diaphora Diffing Workflow (Ghidra / IDA)

1. Open **vulnerable binary** in Ghidra/IDA $\rightarrow$ Export Diaphora SQLite DB (`vulnerable.sqlite`).
2. Open **patched binary** in Ghidra/IDA $\rightarrow$ Export Diaphora SQLite DB (`patched.sqlite`).
3. Launch Diaphora GUI $\rightarrow$ Select `vulnerable.sqlite` and `patched.sqlite` $\rightarrow$ Click **Diff**.

#### Filtering Results

* **Unmatched Functions:** New security validation functions added in patch.
* **Partial Matches (Low Ratio):** Functions modified by the vendor to fix bounds checks, integer overflows, or missing NULL checks.

***

### 2. BinDiff Basic Block Comparison

BinDiff compares binaries using basic block control flow graphs (CFG):

* **Green Blocks:** Identical assembly code.
* **Yellow Blocks:** Modified basic blocks (contains patched instructions!).
* **Red Blocks:** Added or deleted basic blocks.
