# EX-BOOST

> **Category**: Forensics
>
> **Flag**: `bronco{f33lth3h34t}`

> Lost Judgment has been one of my favorite visuals in the Yakuza Series, especially the styles and their colors. As much as Fully Baked loves Boxer, I much prefer the RGB trifecta.
>
> But what's with the heat bar amount on each style? Are they trying to tell me something?
>
> format: `bronco{}`, if you find multiple parts, no spaces.

**Provided files:** `Crane.png`, `Snake.png`, `Tiger.png` — three small icon crops from _Lost Judgment_'s style-select UI, saved here in `challenge/`.

| Crane (円舞)     | Snake (流)      | Tiger (一閃)    |
| -------------- | -------------- | ------------- |
| 154×136 · blue | 111×96 · green | 164×146 · red |

### TL;DR

Each icon hides a leetspeak word in one color channel's **bit-plane**, at a bit position specific to that icon — not always the least-significant bit:

| File        | Icon color | Channel | Bit | Hidden text |
| ----------- | ---------- | ------- | --- | ----------- |
| `Tiger.png` | red        | R       | 0   | `F33L`      |
| `Snake.png` | green      | G       | 2   | `TH3`       |
| `Crane.png` | blue       | B       | 4   | `H34T`      |

Read in **R → G → B** order (the "RGB trifecta" the prompt points at): `F33L` + `TH3` + `H34T` = **"FEEL THE HEAT"**. The prompt says "no spaces" for multi-part flags, so the fragments are concatenated directly:

```
bronco{f33lth3h34t}
```

### Tools Used

* Python 3.12 (`py` launcher on Windows)
* [Pillow](https://pypi.org/project/Pillow/) (`pip install pillow`) — PNG decoding/encoding
* [NumPy](https://pypi.org/project/numpy/) (`pip install numpy`) — bit-plane math
* `file` / manual PNG chunk parsing (stdlib `struct`) — quick structural sanity check
* Visual inspection (no OCR needed — the hidden glyphs render as clean block letters)

No exotic stego tools (zsteg, stegsolve, steghide) were strictly necessary — everything here is doable with Pillow + NumPy in a few short scripts, all included in `scripts/`.

### Reasoning / Walkthrough

#### Step 0 — Read the flavor text as a spec, not just flavor

> "As much as Fully Baked loves Boxer, I much prefer the RGB trifecta."

_Lost Judgment_ has three base fighting styles plus one DLC style (Boxer). The three base styles map directly onto the primary colors, confirmed against the in-game UI and Famitsu's reveal article:

* **円舞 (Enbu / Crane)** — blue
* **流 (Nagare / Snake)** — green
* **一閃 (Issen / Tiger)** — red

"RGB trifecta" = ignore Boxer, focus on Crane/Snake/Tiger, and pay attention to the **R, G, B order** — that phrase turns out to be the key to reassembling the flag later, not just theming.

> "What's with the heat bar amount on each style?"

This reads like a hint that a _number_ is doing work somewhere per style — which turned out to be the **bit position** used to hide data in each image (0, 2, 4 — see below), not an in-game statistic. Chasing this literally as Lost Judgment game trivia (EX Gauge costs, stat bars, etc.) was a dead end — none of that data is consistently documented, and it isn't what the files actually encode.

#### Step 1 — Rule out the obvious forensics wins

Before reaching for steganography, check the boring stuff: corrupted headers, hidden metadata chunks, data appended after `IEND` (a very common trick, see the sibling challenge Magic Ways).

```bash
cd challenge
python ../scripts/01_inspect_png.py
```

Result: all three are well-formed PNGs (valid `89 50 4E 47` signature, correct dimensions, standard `IDAT`/`IEND` structure), no `tEXt`/`zTXt`/`iTXt` chunks, and nothing appended after `IEND`. Nothing here — move on to pixel data itself.

#### Step 2 — Check for LSB steganography via bit statistics

The classic first move for image stego: is the least-significant bit of each channel behaving like noise? Natural image data has roughly a 50/50 split of 0s and 1s in the LSB. A hidden message skews that distribution, because the embedded bits aren't random — mostly background (0) with blocks of glyph (1).

```bash
python ../scripts/02_lsb_stats.py
```

```
=== Tiger.png === shape=(146, 164, 4)
  R LSB ones: 4772/23944 (19.9%)  <-- anomalous (far from 50%)
  G LSB ones: 11816/23944 (49.3%)
  B LSB ones: 12378/23944 (51.7%)
```

Tiger's **red channel LSB sits at \~20%** instead of \~50% — a strong, unambiguous signal. Crane and Snake's channels all sit close to 50% at bit 0 (nothing obviously wrong there yet — foreshadowing that their data isn't in the LSB).

_(Note: the alpha channel reads "100% ones" for every file — that's not stego, it's just a fully-opaque image, alpha ≡ 255 everywhere, so its LSB is trivially always 1. A red herring worth ruling out quickly, not a real anomaly.)_

#### Step 3 — Extract Tiger's anomalous plane and read it

```python
from PIL import Image
import numpy as np

im = Image.open("Tiger.png").convert("RGBA")
arr = np.array(im)
plane = ((arr[:, :, 0] >> 0) & 1) * 255   # red channel, bit 0
Image.fromarray(plane.astype(np.uint8)).resize(
    (im.width * 8, im.height * 8), Image.NEAREST
).save("tiger_r0.png")
```

Result — clean block letters:

**`F33L`**

#### Step 4 — Crane and Snake aren't in the LSB — scan every bit-plane

Since bit-0 stats didn't flag Crane or Snake, the natural next move is to stop assuming "hidden data lives in bit 0" and check **all 8 bits** of **all 3 channels** for each image. Rendering all 24 combinations as a labeled contact sheet makes it trivial to spot where the signal is, even if the statistical skew at that bit is small:

```bash
python ../scripts/03_bitplane_contact_sheet.py
```

This produces one image per file, arranged as an 8-column (bits 0–7) × 3-row (R/G/B) grid.

**Crane** — the text pops out in row 3 (B), column 5 (bit 4):

**Snake** — the text pops out in row 2 (G), column 3 (bit 2):

Zooming into just those cells at full resolution confirms it cleanly:

| Crane → B channel, bit 4 | Snake → G channel, bit 2 |
| ------------------------ | ------------------------ |
|                          |                          |
| `H34T`                   | `TH3`                    |

So the pattern across all three files is: **each icon's own color names the channel, and each style gets its own bit position** (Tiger→bit 0, Snake→bit 2, Crane→bit 4).

#### Step 5 — Assemble the flag

Collecting all three fragments and reading them in **R → G → B** order (per "the RGB trifecta" line in the prompt — Tiger is red, Snake is green, Crane is blue):

```
F33L  +  TH3  +  H34T   =   "FEEL THE HEAT"
```

A fitting pun given the challenge is literally about a color-coded "heat" gauge. The prompt's "no spaces" instruction means concatenate the parts directly (not underscore-join, which is this CTF's usual convention for other challenges — this one is explicit about the difference):

```
bronco{f33lth3h34t}
```

### Full Reproduction

```bash
cd "bronco ctf/EX-BOOST/challenge"
pip install pillow numpy

python ../scripts/01_inspect_png.py             # sanity check: no metadata/appended-data tricks
python ../scripts/02_lsb_stats.py                # flags Tiger's red channel as anomalous
python ../scripts/03_bitplane_contact_sheet.py   # visually locates Crane's and Snake's hidden bit-planes
python ../scripts/04_extract_flag.py             # extracts all 3 planes and prints the flag
```

`04_extract_flag.py` output:

```
Tiger.png: channel=R bit=0 -> 'F33L' (saved ../output/Tiger_bit0_ch0.png)
Snake.png: channel=G bit=2 -> 'TH3' (saved ../output/Snake_bit2_ch1.png)
Crane.png: channel=B bit=4 -> 'H34T' (saved ../output/Crane_bit4_ch2.png)

assembled message: F33L TH3 H34T  ->  "FEEL THE HEAT"
flag: bronco{f33lth3h34t}
```

### Folder Contents

```
EX-BOOST/
├── README.md                  this walkthrough
├── challenge/                 the three files as given
│   ├── Crane.png
│   ├── Snake.png
│   └── Tiger.png
├── scripts/                   reproducible PoC, one file per step
│   ├── 01_inspect_png.py      PNG chunk parser / appended-data check
│   ├── 02_lsb_stats.py        per-channel LSB 0/1 ratio (finds Tiger's anomaly)
│   ├── 03_bitplane_contact_sheet.py   renders all 24 (channel × bit) planes per image
│   └── 04_extract_flag.py     final targeted extraction + flag assembly
└── output/                    generated proof images (from the scripts above)
    ├── Tiger_bit0_ch0.png
    ├── Snake_bit2_ch1.png
    ├── Crane_bit4_ch2.png
    ├── Tiger_bitplanes_contactsheet.png
    ├── Snake_bitplanes_contactsheet.png
    └── Crane_bitplanes_contactsheet.png
```

### Key Takeaways

* Don't stop at bit 0. LSB statistics are a great _first_ filter, but a message can live in **any** bit-plane, and the skew it causes gets diluted (harder to detect statistically) the further you get from the LSB. When bit-0 stats look clean, scan the full 0–7 range before concluding "no LSB stego here."
* A fully-opaque alpha channel will always show up as a 100%-skewed LSB — don't chase that as a false anomaly.
* Flavor text in a forensics prompt is often a literal spec: "RGB trifecta" wasn't just theming, it told you the exact channel-to-file mapping and the order to reassemble the parts.
* When a challenge gives explicit flag-formatting instructions ("no spaces"), don't default to this CTF's usual underscore convention — read the specific instruction for that challenge.
