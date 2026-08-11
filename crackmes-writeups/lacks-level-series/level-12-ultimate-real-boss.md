# Level 12 (Ultimate Real Boss)

> **Category:** RE / Anti-debug + jump-table VM + 152-part chained keygen
>
> **Difficulty:** Hard
>
> **Platform:** Windows x64&#x20;
>
> **Goal:** Enter a **Username** + **152 numeric Parts** to print `[+] Access Granted!` and the clean message `Wow you did it!`.

**TL;DR**

* The license is a **chained recurrence** over 152 integers, seeded by the username:
  * `Part[0] = sum(username_bytes) × 31`
  * `Part[i] = ((i + 0x1337) ^ Part[i-1]) + i×123` (mod 2³²), for i = 1..151
* The success message key = `(Part[151] & 0xFF) ^ 0x3E`; `Wow you did it!` needs `Part[151] & 0xFF == 0x78`.
* Username is free → choose one whose 152-chain lands the last part on `0x78`. Simplest: **username `)`** (byte-sum 41). Feed it + the 152 computed parts.
* Static analysis; the anti-debug (IsDebuggerPresent, timing, DR checks) never matters offline.

***

### 1. Recon

```bash
unzip -P crackmes.one 6a526f062c3088f968e13447.zip   # -> UltimateRealBoss.exe
```

Running it: the title decrypts as `…ULTIMATE 152-Part LICENSE CHECK` and it prompts `Enter Username:`, then `Enter Part 1:` … `Enter Part 152:`. Same anti-debug import set as the previous boss (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `GetThreadContext`, `GetTickCount64`).

***

### 2. The validator VM

`main` calls the validator at `0x140001d50` with `rcx = username`, `rdx = &parts` (a `std::vector<int>`). It's a jump-table state machine (same shape as the previous boss). Extracting its tables (`state_table @ 0x140001f2c`, `jump_table @ 0x140001f08`) and reading the handlers:

| State | Handler  | Check                                                                        |
| ----- | -------- | ---------------------------------------------------------------------------- |
| 0     | `0x1d97` | username non-empty **and** `vector.size == 152` (`end-begin == 0x260` bytes) |
| 1     | `0x1dba` | compute `sum(username_bytes)` (signed, SSE+scalar)                           |
| 2     | `0x1e89` | `Part[0] == sum × 31` (`imul …, 0x1f`)                                       |
| 3     | `0x1ea1` | reset index `i = 1`, enter loop                                              |
| 4     | `0x1eac` | loop guard: `if i >= 152 → success (state 6) else state 5`                   |
| 5     | `0x1ec2` | **per-part check** (below); on pass `i++` and back to state 4                |
| 6     | `0x1ef8` | success (return 1)                                                           |
| 99    | `0x1efb` | fail (return 0)                                                              |

The per-part handler (state 5):

```asm
0x140001ec5  lea r9d, [rbx + 0x1337]        ; i + 0x1337
0x140001ed2  imul ecx, ebx, 0x7b            ; i * 123
0x140001ed5  xor r9d, [rdx + r8*4 - 4]      ; ^ Part[i-1]
0x140001eda  add r9d, ecx                   ; + i*123
0x140001edd  mov ecx, [rdx + r8*4]          ; Part[i]
0x140001ee1  cmp ecx, r9d                   ; Part[i] == ((i+0x1337)^Part[i-1]) + i*123 ?
```

So the full license, in two lines:

```
Part[0] = sum(username_bytes) * 31                       (mod 2**32)
Part[i] = ((i + 0x1337) XOR Part[i-1]) + i*123           (mod 2**32),  i = 1..151
```

Each part is chained off the previous, so the entire 152-tuple is determined by the username's byte-sum. Parts are read as **signed** `int` (`cin >> int`), so values ≥ 2³¹ must be entered as their negative two's-complement form.

***

### 3. Anti-debug (irrelevant offline)

As before, the validator call is wrapped in `GetTickCount64` with a 500 ms budget; exceeding it diverts to a decoy `[!] Debugger Detected!` path (blob XOR `0x4f`). There are also `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` / `GetThreadContext` probes via `GetProcAddress`. We compute everything statically and run the binary normally (no debugger), so none of it triggers.

***

### 4. The message — chained to the last part

On the genuine (fast) success path:

```asm
0x14000277b  mov rax, [rbp-0x78]           ; parts data pointer
0x14000277f  movzx r14d, byte [rax+0x25c]  ; 0x25c = 604 = 151*4  -> low byte of Part[151]
0x140002787  xor r14b, 0x3e               ; message key = (Part[151] & 0xFF) XOR 0x3E
             ; decrypt 15-byte blob with that key, print after "[+] Message: "
```

The blob (`0x1400092a8`, from its initializer at `0x140001560`) is the same 15 bytes as the previous boss: `11 29 31 66 3f 29 33 66 22 2f 22 66 2f 32 67`. Brute-forcing the key:

```
key 0x46 -> "Wow you did it!"     (needs Part[151] & 0xFF == 0x78)
```

Because `Part[151]` is the end of a chain seeded by the username, and **the username is free**, we search byte-sums until the chain's last byte is `0x78` — getting the grant _and_ the clean message. (Levels 6/8/9 couldn't; this finale, like the previous boss, is properly wired.)

***

### 5. Keygen

```python
M = 1<<32
def chain(S):
    p = [(S*31) % M]
    for i in range(1, 152):
        p.append((((i + 0x1337) ^ p[i-1]) + i*123) % M)
    return p
S = next(s for s in range(1, 100000) if chain(s)[151] & 0xFF == 0x78)  # S = 41
```

Smallest clean byte-sum is **41** → username `)` (single char `0x29`). Emit `)` then the 152 parts as signed int32.

* **Username:** `)`
* **Parts:** `chain(41)`, printed as signed 32-bit integers (Part 1 = `1271`, …).

***

### 6. Verification

```bash
python keygen.py | ./UltimateRealBoss.exe   # keygen prints username + 152 parts
```

```
…ULTIMATE 152-Part LICENSE CHECK
Enter Username: Enter Part 1: … Enter Part 152:
[+] Access Granted!
[+] Message: Wow you did it!
```

Confirmed — grant **and** clean message. ✅

***

### Answer

| Field           | Value                                                                                  |
| --------------- | -------------------------------------------------------------------------------------- |
| **Username**    | `)` (any name whose 152-chain gives `Part[151] & 0xFF == 0x78`)                        |
| **Parts**       | `Part[0] = sum×31`, `Part[i] = ((i+0x1337)^Part[i-1]) + i×123` (152 values)            |
| **Message**     | `Wow you did it!`                                                                      |
| **Message key** | `(Part[151] & 0xFF) XOR 0x3E` = `0x46`                                                 |
| **Method**      | Static disassembly, decode the VM, keygen the chain, pick username for a clean message |

Use `keygen.py` to emit the full 153-line input (`username` + 152 parts).

***

### Tools Used

| Tool             | Purpose                                                                                 |
| ---------------- | --------------------------------------------------------------------------------------- |
| `unzip` / `file` | Extract & identify (PE32+ x64)                                                          |
| `pefile`         | Section VAs, locate the validator, read the VM tables + message blob                    |
| `capstone`       | Disassemble the jump-table VM and the chained per-part check                            |
| Python           | Decode the VM, implement the 152-part chain, search the username, brute the message key |
| the binary       | Dynamic confirmation (runs fine without a debugger)                                     |

***

### Takeaways / Methodology

1. **A chained recurrence is still a keygen.** 152 parts looks daunting, but each is a deterministic function of the previous — the whole vector collapses to one free variable (the username's byte-sum). Recover the recurrence and generate.
2. **Reuse recognition pays off.** The VM dispatch, anti-debug timing, `0x3E` message XOR, and the exact 15-byte blob are all lifted from the previous boss. Spotting the repeat made this a fast extension rather than a fresh reverse.
3. **Watch signedness at the I/O boundary.** Parts are read with `cin >> int`; any computed value ≥ 2³¹ must be entered as its negative two's-complement, or the read fails mid-stream and the check aborts.
4. **A free seed beats the flag bug.** The message key hangs off `Part[151]`, i.e. the tail of a username-seeded chain — so choosing the username steers the key to `0x78` and the message decodes cleanly. The finale keeps the "decrypt-on-success" wiring honest.
