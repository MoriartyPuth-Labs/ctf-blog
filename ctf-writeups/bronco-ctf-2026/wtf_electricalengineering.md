# WTF\_ELECTRICALENGINEERING

> **Category**: Misc
>
> **Flag**: `bronco{ov2hhU6mBY}`

> I'm supposed to find the flag somewhere but this guy just sent me two images to try to find it! What the flip, I don't know anything about Electrical Engineering!!

### Challenge

Two PNGs:

* `Challenge.png` — a screenshot of "Table VI: Comparisons of the Radix-4 Booth Designs for Generating One Partial Product Row" from a real IEEE paper (transistor counts, power figures, delay for several Booth multiplier pre-encoder designs).
* `ChallengeCircuit.png` — a transistor-level schematic of a Booth pre-encoder cell (signals `zero_i`, `neg_i`, `x_j`, `nx_j`, `ot_i`, producing `PP_j`).

The flavor text is the whole hint: **you don't need to understand electrical engineering to solve this.** The images are real academic content used purely as a red herring/prop; the actual challenge is steganography followed by a small logic puzzle.

### Reasoning

#### Step 1 — rule out the obvious stego vectors

Standard checklist, all negative:

```python
# PNG chunk dump: only IHDR/IDAT/IEND, no tEXt/zTXt/iTXt, no bytes after IEND
# zlib payload size == width * height * channels exactly (no smuggled extra data)
# LSB bit-planes 0-3 of R/G/B/A, rendered as images: just faint copies of
#   the original picture, no hidden text/QR shape
# HSV saturation channel boosted x5: only re-reveals the *existing* visible
#   text labels in the circuit diagram (antialiasing artifact, not new data)
```

None of the classic "hide a payload in the pixels" tricks panned out. That meant looking somewhere less obvious.

#### Step 2 — check every pixel row for something that shouldn't be there

Both images are mostly a big white margin around the actual figure. Row 0 (the literal top edge of the canvas) _should_ be 100% pure white — nothing is drawn there. Checking it directly:

```python
from PIL import Image
import numpy as np
arr = np.array(Image.open("ChallengeCircuit.png").convert("RGB"))
print(set(map(tuple, arr[0])))
# {(255, 255, 255), (127, 255, 255)}
```

Row 0 of _both_ images contains exactly **two** colors: pure white and a marker cyan `(127, 255, 255)`. A non-background pixel sitting in a row that should be pure margin is about as strong a "look here" signal as steganography gets — this is a deliberately placed one-bit-per-pixel data channel along the top edge, not antialiasing noise (antialiasing noise would never appear on an otherwise perfectly blank row, and wouldn't be a crisp, exact, saturated cyan).

#### Step 3 — decode row 0 as a bitstream

Treat "marker pixel" = 1, "white" = 0, read left-to-right, invert, and pack 8 bits/byte MSB-first (`extract_stego_url.py`):

```
$ python extract_stego_url.py Challenge.png ChallengeCircuit.png
Challenge.png -> b'https://tinyurl.com/hnexnehb'
ChallengeCircuit.png -> b'https://tinyurl.com/3pya79w'
```

Both decode to clean, valid ASCII URLs on the first try — not a coincidence. One is a **dead end**: `3pya79w` redirects to an unrelated, long-defunct University of Technology Sydney course-finder page from 2011 (the connection just times out/resets now — plain link rot, not part of the puzzle). The other, `hnexnehb`, redirects to a **Google Drive folder** named `BroncoCtfChallengeNonCircuit` — the real next step.

#### Step 4 — follow the trail through the Drive folder

The folder contains two files:

* **`hintstable.txt`** — explains that the circuit diagram is meant to be read as an actual Verilog module, gives the bit order for its inputs (`negi` = MSB, then `xj`, then `nxj` \[the previous bit], `oti` = LSB), notes `zeroi` is always 0, and links a pre-built [EDA Playground project](https://www.edaplayground.com/x/ZpgQ) with the real design + testbench already loaded (Icarus Verilog).
* **`inputsequence.b`** (included in this folder, 738 bytes) — the actual stimulus file: 144 whitespace-separated 4-bit binary tokens.

Google Drive's folder view is entirely JS-rendered, so a plain HTTP fetch of the folder page returns no usable file links. Reading it required a real browser session: opening the folder, using the DOM (`data-id` attributes) to recover each file's Drive file ID, then hitting `https://drive.usercontent.google.com/download?id=...&export=download` directly for the raw bytes.

#### Step 5 — pull the real design out of EDA Playground

The playground's editor panes are CodeMirror instances; their live content isn't in the static HTML, so it was read straight out of the browser via `document.querySelectorAll('.CodeMirror')[i].CodeMirror.getValue()`. That gave the actual `design.sv`:

```verilog
module mux(A,B,S,Y);
    input  A,B;
    output  Y;
    input S;
    assign Y = (S)? B : A;
endmodule

module Bronoc(input negi,input xj,input nxj,input ot, output pp);
    wire xorout;
    assign xorout = negi ^ xj;
    mux a1 (nxj, xorout, ot, pp);
endmodule
```

i.e. **`pp = ot ? (negi ^ xj) : nxj`** — exactly the mux/XOR structure drawn in `ChallengeCircuit.png`.

And `testbench.sv` (relevant part):

```verilog
r = $fscanf(in_fd, "%b", v);   // one 4-bit binary token per read
{negi, xj, nxj, ot} = v;       // MSB->LSB
#1;
$fwrite(out_fd, "%b", pp);     // one '0'/'1' char per cycle, no separator
```

Each 4-character token in `inputsequence.b` is _directly_ the 4-bit vector `{negi,xj,nxj,ot}` for one clock cycle (not one bit — the hint text's "MSB will be negi..." line describes the layout _within_ each 4-bit token).

#### Step 6 — realize a simulator isn't actually needed

`inputsequence.b` only ever contains two distinct tokens: `"0000"` and `"1110"`. That's the shortcut:

* Every token has `negi == xj` (both 0, or both 1) → `xorout = negi^xj = 0` for **every single cycle**.
* Every token's last bit (`ot`) is **0**, always.
* The mux's select line is `ot` — since `ot` is always 0, the mux always outputs its `A` input (`nxj`) and the `xorout`/XOR path is dead code for this particular input file.

So for this input:

```
pp = ot ? xorout : nxj  =  nxj  =  1 if token == "1110" else 0
```

The whole combinational circuit reduces to "is this token `1110`?" — one bit per token, no Verilog toolchain required. 144 tokens = 144 bits = exactly 18 bytes, which packs straight to ASCII.

### PoC / Reproduction

```
$ python extract_stego_url.py Challenge.png ChallengeCircuit.png
Challenge.png -> b'https://tinyurl.com/hnexnehb'
ChallengeCircuit.png -> b'https://tinyurl.com/3pya79w'

$ python decode_inputsequence.py inputsequence.b
b'bronco{ov2hhU6mBY}'
```

All three assets (`Challenge.png`, `ChallengeCircuit.png`, `inputsequence.b`) and both scripts are in this folder — no network access needed to reproduce stage 2; stage 1's URLs are dead/redirect targets already resolved above.

### Dead ends worth noting

* A local folder named `electric` turned up early in the investigation containing `chall.py` (a Python `random`/Mersenne-Twister leak-and-attack service) and `checker.py` (an unrelated "get exactly 468 blorgs" logic puzzle). Neither has anything to do with this challenge or with each other — they were leftovers from a different challenge's download that got mixed in. Worth double-checking _which_ challenge a downloaded folder actually belongs to before spending time on its source.
* The `ChallengeCircuit.png` tinyurl (`3pya79w`) is a real, resolvable link but to a page with no relevance to the CTF — almost certainly link rot on a much older shortlink, not a puzzle step.
* Direct `pyzbar`/zbar decode attempts, PNG metadata, and brute-force LSB extraction across the whole image were all reasonable first guesses for "hidden image data" and all correctly ruled out before finding the row-0 channel — a good reminder to check _every_ row/edge of an image, not just the pixel bit-planes, when the obvious stego checks come back clean.

### Tools

* **Pillow / NumPy** — pixel-level image inspection (row/channel/bit-plane extraction)
* **Python's `struct`/`zlib`** — manual PNG chunk parsing and IDAT payload size verification
* **pyzbar** — ruled out direct QR/barcode decode of the raw images
* **Browser automation** (Claude's browser tool) — Google Drive is JS-rendered and doesn't expose file links in static HTML; EDA Playground's code panes are CodeMirror instances with no server-rendered source — both required reading live DOM/editor state, not just fetching HTML
* **`drive.usercontent.google.com/download?id=...`** — direct-download endpoint once a Drive file ID is known
