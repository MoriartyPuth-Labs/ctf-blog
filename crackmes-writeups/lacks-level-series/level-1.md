# Level 1

> **Category:** Reverse Engineering (RE)
>
> **Difficulty:** Easy (1/6)
>
> **Platform:** Windows x64 **Goal:** Recover the password that prints `Access Granted. Welcome!`

**TL;DR — the password is `password`.**

Recovered purely by _static analysis_ — no debugger, no patching, no brute force. The whole thing took under two minutes.

***

### 1. Recon — what are we dealing with?

The challenge ships as a password-protected zip (crackmes.one uses the password `crackmes.one` for every archive).

```bash
unzip -P crackmes.one 6a512980234391ae74f63ae8.zip
# -> level1easy.exe
```

First question on any RE challenge: **what is this file?**

```bash
file level1easy.exe
# level1easy.exe: PE32+ executable (console) x86-64, for MS Windows, 6 sections
```

So it's a 64-bit Windows console application, \~19 KB. Small binary, console I/O — this is going to be a classic "enter the secret" login prompt.

***

### 2. Static Analysis — read the strings first

**Golden rule for easy crackmes: dump the strings before you do anything clever.** Beginner binaries almost always leave the comparison secret as a plaintext string literal.

`strings` wasn't installed in this environment, so a three-line Python one-liner does the same job (extract every printable ASCII run of length ≥ 5):

```python
import re
data = open('level1easy.exe', 'rb').read()
for m in re.finditer(rb'[\x20-\x7e]{5,}', data):
    print(m.group().decode())
```

The interesting output:

```
bad allocation
...
password
=============================
        LOGIN SCREEN
=============================
Enter Password:
Access Granted. Welcome!
Access Denied. Invalid Password.
Press Enter to exit...
C:\Users\knze2\source\repos\crackmetest\x64\Release\crackmetest.pdb
MSVCP140.dll
```

Two things jump out:

1. The UI strings confirm the mental model: a login screen that prints **`Access Granted. Welcome!`** on success and **`Access Denied. Invalid Password.`** on failure.
2. There is a lone string — **`password`** — sitting _just above_ the UI block. It isn't part of any printed message.

The imports (`MSVCP140.dll`, `std::cin`, `std::cout`, `std::string`, `_Xlength_error`) tell us it's a C++ program using `std::string`, which means the check is most likely a simple `if (input == "password")`.

The leaked PDB path is a nice bonus — it tells us the build-machine username (`knze2`) and that the project was literally called `crackmetest`. (The crackme itself is published by author **Lack** in the **Level** series.)

***

### 3. Reasoning — why `password` and not something else?

To confirm `password` is the _comparison target_ and not just noise, look at **where** each string lives in the file. Printing the byte offsets:

```python
import re
data = open('level1easy.exe', 'rb').read()
for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
    s = m.group().decode()
    if any(k in s for k in ['password', 'Access', 'LOGIN', 'Enter', '====']):
        print(hex(m.start()), repr(s))
```

```
0x25c8 'password'
0x25d8 '============================='
0x25f8 '        LOGIN SCREEN         '
0x2618 '============================='
0x2638 'Enter Password: '
0x2651 'Access Granted. Welcome!'
0x2671 'Access Denied. Invalid Password.'
0x2699 'Press Enter to exit...'
```

This layout is the whole solution:

* Every **UI string** lives in one contiguous block from `0x25d8` onward — the compiler laid them out in source order as they're used by `cout`.
* **`password` sits alone at `0x25c8`, immediately before that block**, physically separated from the messages.

That separation is the tell. A string used only in a comparison (`input == "password"`) is emitted independently from the strings streamed to `cout`. The isolated literal right before the print block is the value the program checks your input against.

No printed message ever contains the word "password" by itself, so `password` has exactly one job: it's the secret.

***

### 4. Verification — prove it

Feed the candidate into the binary (first line = password, second `Enter` dismisses the "Press Enter to exit" prompt):

```bash
printf 'password\n\n' | ./level1easy.exe
```

```
=============================
        LOGIN SCREEN
=============================

Enter Password:
Access Granted. Welcome!

Press Enter to exit...
```

**`Access Granted. Welcome!`** — confirmed.

***

### 5. Answer

| Field                         | Value                                         |
| ----------------------------- | --------------------------------------------- |
| **Password**                  | `password`                                    |
| **Method**                    | Static string analysis                        |
| **Author**                    | `Lack` (Level series)                         |
| **Build username (from PDB)** | `knze2` / project `crackmetest` (x64 Release) |

***

### Tools Used

| Tool              | Purpose                                                                   |
| ----------------- | ------------------------------------------------------------------------- |
| `unzip`           | Extract the crackmes.one archive (password `crackmes.one`)                |
| `file`            | Identify binary format/architecture (PE32+ x64)                           |
| Python (`re`)     | Stand-in for `strings`; extract printable runs **and** their file offsets |
| The binary itself | Dynamic confirmation by feeding the candidate password                    |

Everything here also exists as standalone utilities you'd normally reach for: `strings`, `rabin2`/`radare2`, Ghidra, IDA, or `dnSpy` (for .NET). For a Level-1 login check, `strings` + reasoning about string layout is all it takes.

***

### Takeaways / Methodology

1. **`file` first, `strings` second.** For easy RE, this pair solves the majority of challenges before you ever open a disassembler.
2. **Location matters, not just content.** The _offset_ of a string tells you its role: comparison literals are laid out separately from streamed output. Reading the layout beat opening Ghidra.
3. **Don't over-engineer.** No patching the `jne`, no `x64dbg` breakpoint on `strcmp`, no brute force. The plaintext secret was sitting in `.rdata`.
4. **Free intel from PDB paths.** Release builds frequently leak the author's username and project name — useful for attribution and for confirming you're looking at the right binary.
