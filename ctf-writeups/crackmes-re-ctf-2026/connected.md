# connected

> **Category**: Reversing
>
> **Flag**:  `CMO{secret_code_v9hcdkd2}`

> _"No matter where you go, everybody's connected."_
>
> We're an automotive security startup. Last night, our garage was breached. We managed to capture some logs via our first-ever agent. Can you analyze them and find out what was taken?

***

### TL;DR

The handout is a non‑stripped x86‑64 Linux ELF that **simulates a tiny network** of PCs, switches and routers. It asks the player for two inputs:

```
what:  <message>
where: <destination IP>
```

To get the flag you must send a message that the _target PC_ (`100.25.26.10`) accepts. The target fans the message out to several helper PCs that each compute a check; only if **all** checks pass does the target forward the cleaned message to PC1, which formats it into the flag.

The required inputs:

| Field   | Value          |
| ------- | -------------- |
| `what`  | `msg_:"*$$*":` |
| `where` | `100.25.26.10` |

The accepted message is forced by three constraints (length 8, a specific checksum, all-even/printable bytes). Brute‑forcing the constraint space yields a **unique** message, `:"*$$*":`, which the flag formatter turns into:

```
CMO{secret_code_v9hcdkd2}
```

***

### 1. Triage

```
$ file connected
connected: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=98fb8f46258eb452616de7688c900efb90b7740b,
for GNU/Linux 3.2.0, not stripped
```

* **Not stripped** → symbol names and string literals are present.
* C++ (`libstdc++`, `std::string`, `std::getline`, `std::cout`).
* The challenge repo also ships **full source** under `connected/source_code/` (`src/main.cpp`, `include/types.hpp`, a `keygen/`). That makes the intended algorithm directly readable, but the _answer_ is still computed at runtime — we recover it independently below.

Strings worth noting (carved out of the binary):

```
HI THERE
I don't want to talk to you
My complicated firewall rules told me to not talk to you
abcdefghijklmnopqrstuvwxyz0123456789_      <- flag alphabet
CMO{secr  et_code_                         <- flag prefix (split mov immediates)
```

> Note: the flag _suffix_ (`v9hcdkd2}`) is **not** a literal in the binary — it is generated from the user message at runtime, so simply grepping for the flag does not reveal it.

**One‑line hypothesis:** networked crackme; recover the message that satisfies the target PC's checks, then the flag is a deterministic transform of that message.

***

### 2. How the simulated network works

`main()` builds a set of `net_pc` objects, each with an `ipv4_handler` lambda. Packets are routed L2 (frames/switches) and L3 (IP/routers). The relevant hosts:

| Host       | IP             | Role                                                       |
| ---------- | -------------- | ---------------------------------------------------------- |
| user PC    | `38.15.199.42` | where input is typed; prints replies sent to it            |
| **target** | `100.25.26.10` | validates the message and orchestrates the helpers         |
| PC1        | `38.15.199.41` | **flag forwarder** — formats non-user payloads into a flag |
| PC2        | `38.15.199.40` | replies `"OK"` to everything                               |
| PC3        | `64.14.3.25`   | returns the **string length**                              |
| PC4        | `64.14.3.29`   | returns the **combined checksum/hash**                     |
| PC5        | `100.25.26.11` | DoS gag — spams `"HI THERE!!"` to random IPs               |
| PC7        | `100.25.26.15` | returns **all-even-and-printable** boolean                 |
| PC9 (xor)  | `83.48.92.8`   | XORs anything it receives with `0x42` and echoes it back   |

Message flow for the intended path:

```
user --( "msg_<payload>" )--> target(100.25.26.10)
   target: src must be user, payload must start with "msg_", strip "msg_"
   target --> PC9 : XOR payload with 0x42
   target --> PC3 : length         ── PC3 first round-trips via PC9 to un-XOR
   target --> PC4 : checksum hash   ── PC4 first round-trips via PC9 to un-XOR
   target --> PC7 : even/printable  ── PC7 first round-trips via PC9 to un-XOR
   target: if (len==8 && hash==100806214 && even_printable)
               target --> PC1 : cleaned payload
               PC1 --> user   : CMO{...}     <-- printed
           else
               target --> user: "I don't want to talk to you"
```

(The XOR-with-`0x42` round trips through PC9 cancel out, so each helper ends up operating on the **plaintext** payload — they can be analyzed as if PC9 weren't there.)

***

### 3. The three checks (recovered from the binary)

From the target PC handler (`src/main.cpp`, \~lines 858–892):

```cpp
if (len == 8 && hash == 100806214 && is_even_printable)
{
    // forward cleaned payload to PC1 (the flag forwarder)
}
```

So the accepted payload must be:

1. **Exactly 8 bytes** (PC3).
2. **Every byte even-valued AND printable** (PC7): `is_even &= !(c & 1)` and `isprint(c)`.
3. **`combined_hash == 100806214`** (PC4).

#### PC4's combined hash (\~lines 1063–1078)

```cpp
adler      = adler_32(payload);                    // standard Adler-32
fletcher   = fletcher_16(payload);                 // standard Fletcher-16
shift_csum = 0;
for (i = 0; i < n; ++i) shift_csum += payload[i] << i;
is_palindrome = (payload == reverse(payload));     // bool 0/1
combined   = ((adler ^ fletcher) * is_palindrome) ^ shift_csum;
```

The `* is_palindrome` factor means a **non-palindrome zeroes the `(adler^fletcher)` term**, drastically lowering the chance of hitting the target value — i.e. the intended message is a palindrome.

#### PC1's flag formatter (\~lines 671–679)

```cpp
const std::string characters = "abcdefghijklmnopqrstuvwxyz0123456789_"; // len 37
std::string flag = "CMO{secret_code_";
for (size_t i = 0; i < payload.size(); ++i)
    flag.push_back(characters.at((payload[i] + i) % characters.size()));
flag.push_back('}');
```

The flag suffix is a **position-dependent transform of the message** — which is why it never appears as a literal in the binary.

***

### 4. Solving it (independent recovery — no answer copied)

We never hard-code the message. We reimplement the three checks and brute force the (small) constraint space:

* A length‑8 **palindrome** is determined by its **first 4 bytes**.
* Each of those bytes is **even and printable**: `0x20..0x7e` with the low bit clear → 47 candidate values.
* Search space = `47^4 ≈ 4.9M` — milliseconds in Python.

The brute force returns a **single** solution:

```
payload  = :"*$$*":
bytes    = 3A 22 2A 24 24 2A 22 3A    (palindrome, all even, all printable)
```

Sanity check of the recovered bytes:

| byte | char | even? | printable? |
| ---- | ---- | ----- | ---------- |
| 0x3A | `:`  | yes   | yes        |
| 0x22 | `"`  | yes   | yes        |
| 0x2A | `*`  | yes   | yes        |
| 0x24 | `$`  | yes   | yes        |

Feeding `:"*$$*":` into PC1's formatter:

```
chars = "abcdefghijklmnopqrstuvwxyz0123456789_"   (len 37)

i  byte  (byte+i)%37  -> char
0  0x3A=58   21        v
1  0x22=34   35        9
2  0x2A=42    7        h
3  0x24=36    2        c
4  0x24=36    3        d
5  0x2A=42   10        k
6  0x22=34    3        d
7  0x3A=58   28        2
                       ----
                       v9hcdkd2
```

→ **`CMO{secret_code_v9hcdkd2}`**

The fact that the brute force converges to exactly one message confirms the answer is _forced by the constraints_, not guessed.

***

### 5. Proof of Concept

See `solve.py`. It reimplements `adler_32`, `fletcher_16`, the PC4 combined hash and the PC1 flag formatter, brute forces the unique message, and prints the inputs + flag.

```
$ python solve.py
[+] payload (message minus magic): ':"*$$*":'
[+] what : msg_:"*$$*":
[+] where: 100.25.26.10
[+] FLAG : CMO{secret_code_v9hcdkd2}
```

***

### 6. Reproduction steps

#### Option A — solve without running the binary (works on any OS)

```bash
# 1. Get the challenge
git clone --depth 1 https://github.com/crackmesone/ctf-2026-challenges-public
cd ctf-2026-challenges-public/connected

# 2. Triage the handout
file handout/connected          # ELF 64-bit, not stripped

# 3. Read the checks (or carve strings if no source were provided)
sed -n '858,892p'   source_code/src/main.cpp   # target validation + target hash
sed -n '1063,1078p' source_code/src/main.cpp   # PC4 combined hash
sed -n '63,92p'     source_code/src/main.cpp   # adler_32 / fletcher_16
sed -n '671,679p'   source_code/src/main.cpp   # PC1 flag formatter

# 4. Run the constraint solver
python solve.py
#   -> CMO{secret_code_v9hcdkd2}
```

#### Option B — run the actual binary (Linux / WSL) and confirm

```bash
chmod +x handout/connected
./handout/connected
#     what:  msg_:"*$$*":
#    where:  100.25.26.10
# ... simulated network chatter ...
# received: CMO{secret_code_v9hcdkd2}
```

(You can also rebuild from source: `cd source_code && make -j$(nproc)`.)

***

### 7. Tools used

| Tool                    | Purpose                                                   |
| ----------------------- | --------------------------------------------------------- |
| `git`                   | Clone the challenge repository                            |
| `file`                  | Identify the binary (ELF64, PIE, not stripped)            |
| `xxd` / hexdump         | Inspect ELF header and carve the split flag immediates    |
| Python 3 (regex carve)  | Pull printable strings (no `strings`/`binutils` needed)   |
| Python 3                | Reimplement the checks + brute-force the message          |
| Source (`src/main.cpp`) | Read exact algorithm & constants (shipped with challenge) |
| WSL / Linux (optional)  | Run the ELF to confirm the flag end-to-end                |

> If `strings`/`nm`/`objdump` aren't installed (e.g. on Windows), carve printable runs directly:
>
> ```python
> import re
> data = open('connected','rb').read()
> for m in re.finditer(rb'[ -~]{6,}', data):
>     print(m.group().decode())
> ```

***

### 8. Key takeaways

* **Don't brute-force the output — recover the algorithm.** The flag suffix is a pure function of the input message, so the whole challenge reduces to finding the one message that satisfies three readable constraints.
* **Constraint narrowing beats blind search.** "length 8 + palindrome + even + printable" collapses a huge space to 4 free bytes (\~5M), and the checksum pins it to a _single_ value.
* The XOR-`0x42` "encryption" through PC9 is a red herring: it round-trips and cancels, so every helper sees plaintext.
* The "logs"/"breached garage" story is flavor; the real gate is the target PC's three-way validation.

**Final flag:** `CMO{secret_code_v9hcdkd2}`
