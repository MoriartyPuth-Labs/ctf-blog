# Golfing

> **Category**: Pwn
>
> **Flag:** `LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10O2TIWbXI?si=FRemo2lpPXvkUyGh::#RISC!@2026%_^~}`

### The setup

Connect and you get a one-line prompt: `Send your RISC-V ELF (base64):` . The challenge bundle is a Linux kernel built for RISC-V 64-bit, an initramfs, and a QEMU launch script — the remote service takes a base64-encoded ELF, runs a battery of checks on it, boots it inside a guest VM, and shows you whatever it prints.

The checks are the whole game, and they're deliberately nasty for a "golfing" challenge:

* The ELF has to be tiny overall.
* The `.text` section is capped at **0x71 (113) bytes**.
* No `ecall` bytes anywhere in the file.
* No `ebreak`, and no _compressed_ `ebreak` either (RISC-V's 16-bit instruction encoding has its own separate breakpoint opcode, so both forms have to be avoided).

That `ecall` ban is the interesting part. On RISC-V, `ecall` is _the_ instruction that makes a syscall — there is no other way to ask the kernel to do something. Ban it from the file you control, and you'd think there's no way to call `openat`/`read`/`write` to get at `/flag.txt` at all.

### The trick: syscalls without an `ecall` in your file

The `ecall` instruction only has to be _absent from your ELF_ — it doesn't have to be absent from the process's address space. Every Linux process gets a **VDSO** (virtual dynamic shared object) mapped in by the kernel itself, and that mapping is real, executable, kernel-supplied code. It's not something the challenge's file-content scanner ever looks at, because it isn't part of your file.

Somewhere inside that VDSO sits an ordinary two-instruction gadget:

```asm
ecall
ret
```

Find its address, `jalr` into it whenever you need a syscall, and the `ret` at the end sends control straight back to your own shellcode afterward — for all practical purposes, a callable syscall function that the validator never gets to inspect, because the bytes never touch your file.

### Finding the VDSO without any syscalls of your own

Getting the VDSO's base address is itself a small puzzle, since you can't just call `getauxval()` — that's libc, and there's no libc here, just raw shellcode dropped straight at the ELF's entry point.

The answer is already sitting on the stack when your shellcode starts. The Linux process-startup stack layout, from `sp` upward, is:

```
argc
argv[]          (argc pointers, NULL-terminated)
envp[]          (NULL-terminated)
auxv[]          (Elf64_auxv_t pairs: {type, value}, terminated by AT_NULL)
```

The **auxiliary vector** is the kernel's way of handing a freshly-`exec`'d process a pile of facts about itself without syscalls — page size, UID, hardware capability bits, and, critically, `AT_SYSINFO_EHDR` (type **33**), whose value is the VDSO's base address. So the shellcode just walks past `argc`, then `argv`'s NULL terminator, then `envp`'s NULL terminator, scanning `auxv` pairs until it hits type 33, and takes that entry's value as the VDSO base.

Add a fixed offset (`+0xc50`, found by disassembling the VDSO once ahead of time) to get the address of the `ecall; ret` gadget, and every syscall from then on is just: set up `a0..a3`/`a7` (RISC-V's syscall-argument and syscall-number registers) and `jalr ra, syscall_gadget`.

### The actual payload: three syscalls

Once syscalls are available, reading the flag is the easy part — `openat` → `read` → `write`, RISC-V syscall numbers 56 / 63 / 64:

```
openat(AT_FDCWD=-100, "/flag.txt", O_RDONLY, 0)   -> fd in a0
read(fd, buffer, 0x100)                            -> bytes read in a0
write(1, buffer, bytes_read)
```

Worth calling out: the `read` size started life as `0x40` (64 bytes) in testing, and the output came back truncated — the flag is longer than 64 bytes. Bumping the immediate in `li a2, 0x40` to `0x100` fixed it. That's the kind of thing that's easy to lose an hour to if you don't notice the output is simply _cut off_ rather than wrong.

### Packing it into 113 bytes

The `.text` cap (`0x71` bytes) is tight enough that the shellcode itself has to be hand-assembled, not compiler output — there's no room for a compiler's calling convention overhead. The actual payload comes in at 88 bytes: find `AT_SYSINFO_EHDR`, compute the gadget address, run all three syscalls, done — with the literal bytes of `"/flag.txt\0"` packed in at the end of the same blob, since there's no separate data section to spare.

That shellcode gets wrapped in the smallest ELF64 that will actually load: a hand-built header (`ET_EXEC`, entry point `0x100b0`) and exactly two program headers — one `R+X` segment holding the header/program-header data plus the shellcode, one `R+W` segment (zero bytes on disk, `0x1000` bytes in memory) to act as a scratch read buffer for the `read` syscall without needing to store any buffer contents in the file at all.

### Solving it

`solve.py` builds that ELF byte-for-byte with `struct.pack_into` (headers, segments, the shellcode blob, and a minimal section-header table so tools that expect one don't choke), self-checks it against the same limits the remote enforces (size window, `.text` length, the three banned opcode-byte patterns, and a scan for any run of four identical bytes in a row — apparently an additional anti-pattern check on the remote side), then base64-encodes it and sends it over the wire with a small connect/retry loop:

```
$ python3 solve.py 15.235.202.47 9002
[+] text size : 88 bytes
[+] ELF size  : 456 bytes
[+] Base64    : 608 bytes
[*] connecting to 15.235.202.47:9002 (attempt 1/5)
Send your RISC-V ELF (base64): LYKNCTF{"The moon is beautiful, isn't it?"::...}
<FLAG>LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10O2TIWbXI?si=FRemo2lpPXvkUyGh::#RISC!@2026%_^~}
```

Verified live: the remote instance was still up and this ran clean end-to-end, producing the exact flag above.

### Tools

* Plain Python `struct`/`socket`/`base64` — the whole exploit is just binary layout and a TCP connection, no disassembler needed since the shellcode was hand-assembled directly to bytes
* QEMU/RISC-V knowledge for the VDSO gadget offset and the process startup stack layout (argc/argv/envp/auxv), which is what makes finding a syscall path possible without ever writing `ecall` into the file
