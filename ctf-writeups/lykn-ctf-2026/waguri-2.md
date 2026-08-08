# Waguri 2

> **Category**: Reversing
>
> **Flag:** `LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}`

### Overview

This challenge provides a file `output1.txt` containing 23,000 tokens — each token is the full name of a character from the manga _"Kaoru Hana wa Rin to Saku"_ (薫る花は凛と咲く). The goal is to determine the correct mapping from names to Brainfuck commands, then find the 34-character input that makes the resulting BF program halt.

The four characters used as tokens are:

* **Waguri Kaoruko** (薫子)
* **Kaoru Hana** (花)
* **Natsusawa Saku** (夏生)
* **Tsumugi Rintaro** (紬)
* **Yorita Ayato** (綾人)
* **Hoshina Subaru** (昴)

### Step-by-Step Solution

#### Step 1: Token Discovery & Verification

The file `output1.txt` contains newline-separated character names. We start by loading and counting them:

```python
with open("output1.txt") as f:
    content = f.read().strip()
tokens = content.split()

from collections import Counter
counts = Counter(tokens)
# Results:
# usami_shohei: 5893   (note: Usami is a 7th character not in the original 6!)
# natsusawa_saku: 5893
# tsumugi_rintaro: 5896
# waguri_kaoruko: 2664
# yorita_ayato: 1310
# hoshina_subaru: 1310
# kaoru_hana: 34
```

**Key observations:**

* Total: 23000 tokens = 23000 BF commands
* `yorita_ayato` = `hoshina_subaru` = 1310 → they pair as `[` and `]` (balanced brackets)
* `kaoru_hana` = 34 → likely `,` (input read for a 34-character flag)
* The remaining 4 tokens map to `+`, `-`, `>`, `<` in some permutation

#### Step 2: Structural Analysis — Identifying the Mapping

We test the candidate mapping (let's call it **Mapping B**):

| Token            | BF  |
| ---------------- | --- |
| usami\_shohei    | `>` |
| natsusawa\_saku  | `<` |
| tsumugi\_rintaro | `-` |
| waguri\_kaoruko  | `+` |
| kaoru\_hana      | `,` |
| yorita\_ayato    | `[` |
| hoshina\_subaru  | `]` |

```python
mapping_b = {
    'usami_shohei': '>',
    'natsusawa_saku': '<',
    'tsumugi_rintaro': '-',
    'waguri_kaoruko': '+',
    'kaoru_hana': ',',
    'yorita_ayato': '[',
    'hoshina_subaru': ']',
}
bf_b = ''.join(mapping_b[t] for t in tokens)
```

We then analyze loop patterns in the resulting BF code:

```python
def analyze_code(code):
    bracket_map = {}
    stack = []
    for i, c in enumerate(code):
        if c == '[':
            stack.append(i)
        elif c == ']':
            j = stack.pop()
            bracket_map[i] = j
            bracket_map[j] = i

    loops = []
    for i in range(len(code)):
        if code[i] == '[':
            body = code[i+1:bracket_map[i]]
            if len(body) <= 80:
                loops.append(body)
    return loops

from collections import Counter
loop_counts = Counter(loops_b)
```

**Results confirm Mapping B:**

| Pattern          | Count | Meaning                                                          |
| ---------------- | ----- | ---------------------------------------------------------------- |
| `[-]`            | 790   | Clear cell to 0                                                  |
| `[--]`           | 361   | Divide by 2 (subtract 2 per iteration)                           |
| `[-<+>]`         | 34    | Copy-left: move value one cell left (one per input character!)   |
| `[>+[-]<]`       | 12    | Guard loop — infinite if entered, skipped when validation passes |
| `[<+++>-]`       | 19    | Multiply left cell by 3                                          |
| `[<++++>-]`      | 15    | Multiply left cell by 4                                          |
| `[>>+[-]<<]`     | 7     | Another guard loop                                               |
| `[>>>++[--]<<<]` | 9     | Complex transformation                                           |
| `[><]`           | 6     | Validation guard (infinite if cell ≠ 0)                          |

The patterns `[-<+>]` and `[>+[-]<]` are standard BF idioms that only work with this exact mapping:

* `[-<+>]` = `[ - < + > ]` → tsumugi=natsusawa=waguri=usami= — yes!
* `[>+[-]<]` = `[ > + [ - ] < ]` → usami=wagugi=yorita=tsumugi=hoshina=natsusawa= — yes!

No other permutation produces these specific patterns.

#### Step 3: Finding Input Values by Segment Isolation

The program reads 34 input characters (one per `kaoru_hana`). Each character is processed by a segment of BF code between two consecutive commas. We extract these segments and brute-force the correct byte value for each:

```python
comma_pos = [i for i, c in enumerate(bf_b) if c == ',']
segments = [bf_b[comma_pos[i]+1:comma_pos[i+1]] for i in range(len(comma_pos)-1)]
segments.append(bf_b[comma_pos[-1]+1:])  # after last comma

def find_halt_values(segments):
    results = []
    for idx, seg in enumerate(segments):
        stack = []; jump = {}
        for i, c in enumerate(seg):
            if c == '[': stack.append(i)
            elif c == ']' and stack:
                j = stack.pop(); jump[i] = j; jump[j] = i

        found = None
        for v in range(256):
            tape = [0]*300; ptr = 150
            tape[ptr] = v

            steps = 0; ip = 0
            while 0 <= ip < len(seg) and steps < 500000:
                c = seg[ip]
                if c == '>': ptr += 1
                elif c == '<': ptr -= 1
                elif c == '+': tape[ptr] = (tape[ptr] + 1) & 0xFF
                elif c == '-': tape[ptr] = (tape[ptr] - 1) & 0xFF

                if c == '[' and tape[ptr] == 0:
                    ip = jump.get(ip, ip)
                elif c == ']' and tape[ptr] != 0:
                    ip = jump.get(ip, ip)
                steps += 1; ip += 1

            if ip >= len(seg):
                found = v
                ch = chr(v) if 32 <= v < 127 else f'\\x{v:02x}'
                print(f"seg {idx}: value={v} ('{ch}') in {steps} steps")
                break

        if found is None:
            print(f"seg {idx}: NOT FOUND")
            results.append(None)
        else:
            results.append(found)
    return results

vals = find_halt_values(segments)
```

#### Step 4: The Flag

Each segment independently validates one character. Running the brute-force for all 34 segments produces:

```
seg 0: value=76  ('L') in 734 steps
seg 1: value=89  ('Y') in 1401 steps
seg 2: value=75  ('K') in 1345 steps
seg 3: value=78  ('N') in 904 steps
seg 4: value=67  ('C') in 718 steps
seg 5: value=84  ('T') in 1622 steps
seg 6: value=70  ('F') in 1078 steps
seg 7: value=123 ('{') in 1686 steps
seg 8: value=75  ('K') in 1387 steps
seg 9: value=52  ('4') in 1175 steps
seg 10: value=48 ('0') in 1153 steps
seg 11: value=82 ('R') in 1234 steps
seg 12: value=85 ('U') in 780 steps
seg 13: value=95 ('_') in 868 steps
seg 14: value=72 ('H') in 690 steps
seg 15: value=52 ('4') in 1206 steps
seg 16: value=78 ('N') in 980 steps
seg 17: value=52 ('4') in 1033 steps
seg 18: value=95 ('_') in 1050 steps
seg 19: value=87 ('W') in 827 steps
seg 20: value=52 ('4') in 972 steps
seg 21: value=95 ('_') in 1002 steps
seg 22: value=82 ('R') in 1363 steps
seg 23: value=49 ('1') in 1000 steps
seg 24: value=78 ('N') in 1021 steps
seg 25: value=95 ('_') in 1082 steps
seg 26: value=84 ('T') in 1038 steps
seg 27: value=48 ('0') in 1482 steps
seg 28: value=95 ('_') in 1384 steps
seg 29: value=83 ('S') in 1279 steps
seg 30: value=52 ('4') in 804 steps
seg 31: value=75 ('K') in 1004 steps
seg 32: value=85 ('U') in 969 steps
seg 33: value=125 ('}') in 1248 steps
```

**Flag:** `LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}`

Running the **full** BF program with this 34-byte input halts cleanly in **37,565 steps**, confirming the solution.

#### Decoding the Flag

The inner part uses leet speak (1337):

| Leet  | Plain | Meaning             |
| ----- | ----- | ------------------- |
| K40RU | KAORU | Waguri Kaoruko      |
| H4N4  | HANA  | Kaoru Hana          |
| W4    | WA    | Japanese particle は |
| R1N   | RIN   | Tsumugi Rintaro     |
| T0    | TO    | Japanese particle と |
| S4KU  | SAKU  | Natsusawa Saku      |

**"KAORU\_HANA\_WA\_RIN\_TO\_SAKU"** — "The Fragrant Flower Blooms with Dignity" (薫る花は凛と咲く), referencing all four main characters.

#### Python Scripts

| File              | Purpose                                                                                                    |
| ----------------- | ---------------------------------------------------------------------------------------------------------- |
| `solve.py`        | **Main solver** — maps tokens → BF, brute-forces all 34 segments, prints flag, verifies full program halts |
| `analyze_bf.py`   | Token counting + loop pattern analysis (confirms Mapping B)                                                |
| `trace_ip.py`     | IP-level tracer — shows where execution gets stuck (`[><]` guards)                                         |
| `fast_emulate.py` | Segment brute-force — **first to find value 76 = 'L'**                                                     |
| `full_bf_run.py`  | Tests full program, discovers segments need different values                                               |

**Usage:** `python solve.py` (requires `output1.txt` in same directory)
