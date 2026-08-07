# d3gomoku

**Event**: `D3Ctf 2026` | **Category**: `Reverse Engineering`

---

# d3gomoku

## Summary

**d3gomoku** is a Windows Kernel Driver Reverse Engineering challenge (`d3gomoku.sys`). The driver exposes public IOCTLs for a Gomoku game, while hiding the real flag verification logic inside an embedded second-stage PE kernel module. The second-stage module employs Extended Page Table (EPT) hooks, dual-view constant switching (`vmfunc`), MSR salt spoofing (`rdmsr`), base-37 digit folding over 10 game rounds, and 39-byte body SHA-256 double-check verification.

---

## Technical Details & Architecture Analysis

### 1. Overall Structure
The public driver handles game IOCTLs:
- `0x222040`: `initialize`
- `0x222044`: `reset`
- `0x222048`: `move`
- `0x22204C`: `takeback`
- `0x222050`: `query`

Device dispatch logic resides at `0x1400319C0`. Main move branch enters `0x140036E1F` and connects player placements to the AI engine at `0x1400372B0`. The hidden gate string `ACELETMEIN` at `0x1400312F0` is a decoy. Real EPT hook entry point is at `0x1400311C0`.

### 2. Dual Views in Second-Stage PE Module
The embedded second-stage kernel payload (entry `0x140018330`, verification body `0x1400184F0`) splits page execution into two memory views via Hypervisor `vmfunc`:
- **Clean / Read View**: Statically visible in IDA, shows fake decoy constants:
  `0x3CA5218358266D71`, `0x409B7C7DB5881627`
- **Hook / Execute View**: Active during execution, contains the real constants:
  `0x44EA257DE1CEFB27`, `0xEED3C641A4C3A7A7`

The bridge code at `0x140010841` switches execution back to the clean view while forwarding real constants in registers `R10`/`R11` to `0x1400184F0`.

### 3. Salt & Base-37 Digit Folding
Static salt material is `0x00D31145`. The spoofed `rdmsr` return is `0x00D10155`.
$$\text{Salt} = \text{0x00D31145} \oplus \text{0x00D10155} = \text{0x00021010}$$

For each round $i$, Human move $(H_x, H_y)$ and AI move $(A_x, A_y)$ are combined:
$$a_i = H_x + A_x, \quad b_i = H_y + A_y$$

And encoded into two 64-bit base-37 accumulators:
$$x_i = (a_i + p_i + 2b_i + c_i) \bmod 37$$
$$y_i = (b_i + q_i + 3a_i + d_i) \bmod 37$$
$$X = X \cdot 37 + x_i, \quad Y = Y \cdot 37 + y_i$$

Since $37^{10} < 2^{64}$, no overflow wrapping occurs within 10 rounds. Inverting the 64-bit target values into base-37 digits yields a unique 10-round sum sequence $(a_i, b_i)$:
$$(5,1), (3,8), (3,12), (5,12), (0,18), (0,12), (9,3), (8,5), (6,7), (5,4)$$

---

## Walkthrough & Solution Steps

### Step 1: Invert Base-37 Accumulators to Recover Target Coordinate Sums

Inverting $X$ and $Y$ back to base-37 digits recovers the unique coordinate sum for each round:

```python
# Base-37 Inversion
def recover_round_sums(target_X, target_Y, salt):
    sums = []
    p_prev, q_prev = (salt >> 1) & 0xF, (salt >> 5) & 0xF
    for i in range(10):
        # Calculate round tweak constants c_i, d_i from salt
        c_i = (((salt >> ((i & 3) * 8)) & 0xFF) + 7 * i + 0x13) % 37
        d_i = (((salt >> (((i + 1) & 3) * 8)) & 0xFF) + 11 * i + 0x1D) % 37
        
        # Solve linear system mod 37 for (a_i, b_i)
        # u = (digitX - c_i - p_i) mod 37
        # v = (digitY - d_i - q_i) mod 37
        # a_i = (2 * v - u) * inv5 mod 37
        # b_i = (v - 3 * a_i) mod 37
        # ...
    return sums
```

### Step 2: Simulate Gomoku AI Engine to Find Winning Move Sequence

We run a Gomoku engine simulation to decompose each $(a_i, b_i)$ sum pair into legal player placements and actual AI responses. Exactly one 10-round move sequence satisfies both Gomoku rules and the target sum verification:

| Round | Human Move $H(x, y)$ | AI Move $A(x, y)$ | Sum $(H_x+A_x, H_y+A_y)$ |
| :---: | :---: | :---: | :---: |
| 1 | **(2, 0)** | **(3, 1)** | (5, 1) |
| 2 | **(0, 6)** | **(3, 2)** | (3, 8) |
| 3 | **(0, 9)** | **(3, 3)** | (3, 12) |
| 4 | **(2, 8)** | **(3, 4)** | (5, 12) |
| 5 | **(0, 8)** | **(0, 10)** | (0, 18) |
| 6 | **(0, 7)** | **(0, 5)** | (0, 12) |
| 7 | **(4, 1)** | **(5, 2)** | (9, 3) |
| 8 | **(4, 3)** | **(4, 2)** | (8, 5) |
| 9 | **(4, 5)** | **(2, 2)** | (6, 7) |
| 10 | **(1, 0)** | **(4, 4)** | (5, 4) |

### Step 3: Flag Decryption & Body Verification

Playing this exact sequence causes the driver to write the final 39-byte body to the Windows registry. The updated 39-byte ASCII hex string is:
`48657935683464307777346c6b33522d31643265666164642d616165662d7a656e752d73313030`

Interpreting the hex string as ASCII text yields:
`Hey5h4d0ww4lk3R-1d2efadd-aaef-zenu-s100`

Wrapping it in the `d3ctf{...}` format gives the final flag.

---

## Flag

```
d3ctf{Hey5h4d0ww4lk3R-1d2efadd-aaef-zenu-s100}
```
