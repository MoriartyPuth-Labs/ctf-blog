# H34p D3v1l

> **Category**: pwn
>
> **Flag:** `LYKNCTF{0utsm4rt3d_th3_h34p_d3v1l}`

> Even demons make mistakes. The Heap Devil has invited you to play a dangerous game with his "unbreakable" contracts. Outwit the master of trickery, beat him at his own game, and escape with the flag! `nc 15.235.202.47 9009`

### Binary

`Heap_devil` — x86-64 ELF, dynamically linked, **not stripped**, shipped with its own `libc.so.6` (glibc **2.39**, Ubuntu build).

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

Full RELRO kills a GOT overwrite outright, and glibc 2.34+ removed `__malloc_hook`/`__free_hook`, so the two classic "one write and you're done" heap wins are both off the table. Whatever this is, it has to end in a leak-everything-then-ROP chain.

### Note structure

The program manages up to a handful of "notes" through a fixed-size global array. Each entry is 0x18 bytes:

```c
typedef struct {
    int   in_use;   // +0x00
    int   size;     // +0x04
    int   id;       // +0x08
    int   _pad;      // +0x0c
    char *data;      // +0x10
} Note;
```

Menu: create / view / edit / delete / **change size** / exit. The size handler is the interesting one — it does **not** call `realloc()`. It `free()`s the old buffer, `malloc()`s a new one, and swaps the pointer in place. That's a free the program itself performs on our behalf, which matters once we start hunting for a bug.

### The bug: off-by-one + a delete that doesn't clean up

`view_note()` and `edit_note()` both validate the index the same (wrong) way:

```c
if (index < 0 || index > num_notes) {   // should be >=
    puts("Invalid index!");
    return;
}
```

`index == num_notes` slips through — one past the last live note.

`delete_note()` shifts every entry _after_ the deleted one down by one slot and decrements `num_notes`, but it never clears the slot that falls out of the logical array (`notes[num_notes]` after the decrement). Two consequences fall out of that, depending on _which_ index you delete:

* Deleting anywhere **but** the last index shifts a later entry down, leaving a **duplicate** — the same live pointer now readable at two indices (one in-bounds, one only reachable through the off-by-one).
* Deleting the **current last** index never touches the shift loop at all (nothing after it to move). The stale slot keeps the exact `in_use`/ `data` values the note had **before** it was freed — a plain use-after- free, reachable at `notes[num_notes]` through the same off-by-one.

The second case is strictly easier to reason about (no shifting to track), so the whole exploit standardizes on it: **only ever delete whatever is currently the last note.** `view(num_notes)` becomes a UAF _read_; `edit(num_notes)` becomes a UAF _write_ — directly onto a freed tcache chunk's contents, including its mangled `fd` pointer.

### Building an arbitrary-allocation primitive

glibc 2.39's tcache still safe-links free-list pointers: `stored = ptr ^ (chunk_address >> 12)`, keyed on the address of the chunk holding the pointer — not a single global secret, so every chunk needs its own key derived at the point you're about to use it.

The primitive, `poison_alloc(size, target)`, forces the _next_ `malloc(size)` to hand back memory at an attacker-chosen `target`:

1. Create `A`, then `B` (two same-size notes — same tcache bin).
2. Delete `B` (current last index → clean free, no shift).
3. Delete `A` (now the current last index too → also a clean free). tcache for this size is now a genuine two-entry list, `A → B`, with `A` at the head. `A`'s stale slot (`notes[num_notes]`) aliases the freed chunk.
4. Read that stale slot: the first 8 bytes are `A`'s mangled `fd`, i.e. `key = A_ptr >> 12` (since `A`'s recorded next is `B`, and we know nothing is hidden — we only need `A`'s own key, not `B`'s address, to move on).
5. Edit that stale slot with `key ^ target` — `A`'s `fd` now decodes to `target` instead of `B`.
6. Allocate twice more: the first `malloc(size)` pops `A` (housekeeping, throwaway data); the second pops `target`, with our payload as its _initial contents_.

Two extra glibc details had to be handled to make this reliable:

* **16-byte alignment.** `tcache_get()` rejects (aborts on) any unaligned chunk pointer. `target` gets aligned down to the nearest 16, and callers track the resulting byte shift to know where their data actually landed.
* **The zeroed key window.** `tcache_get()` also zeroes bytes `[+8, +16)` of whatever it hands back (its own double-free "key" bookkeeping). For _reads_, if the natural alignment would put our target's real data in that window, back off by another 16 bytes so the interesting bytes land outside it. Writes don't care — our payload overwrites that window anyway.

Every size class used below is distinct from the others, so none of these poison rounds share (and corrupt) another round's tcache bin.

### Leak #1: heap base

Free a _lone_ chunk (empty tcache list for that size) and read its stale slot directly — no poisoning needed yet. An empty list means `mangled_fd = 0 ^ (chunk_ptr >> 12) = chunk_ptr >> 12`, and since the chunk sits in the heap's very first page, `chunk_ptr >> 12 == heap_base >> 12`:

```python
heap = u64(vw(idxH)[:8]) << 12
```

### Leak #2: libc base, for free, courtesy of `main()`

`main()` calls `fopen("/dev/random", "r")` once at startup and never touches the resulting `FILE *` again — it's a pure red herring for anything _except_ as a leak source. `fopen` heap-allocates that `FILE` struct, and its vtable field (a fixed offset into the struct) is a libc-relative pointer sitting in plain heap memory the whole time the program runs. Since it's never read from or written to again, poisoning a `malloc()` onto it and reading its vtable back is entirely non-destructive:

```python
idxT, shift = poison_alloc(0x48, heap + 0x360, b"\n")
vtab = u64(vw(idxT)[shift + 0x18 : shift + 0x20])
libc.address = vtab - 0x202030     # offset of _IO_file_jumps in this libc
```

(The official approach fills tcache to force a chunk into the unsorted bin and leaks `main_arena` from there — also valid, just a different free libc pointer. This one needs no bin-filling at all.)

### Leak #3: stack address via `environ`

Point the same primitive at `libc.sym['environ']` and read the pointer it holds — libc's `environ` global stores the process's actual stack address:

```python
idxT, shift = poison_alloc(0x28, libc.sym.environ, b"\n")
environ_val = u64(vw(idxT)[shift : shift + 8])
```

### Finding the saved return address

`main()`'s dispatch loop calls every menu handler (`create_note`, `edit_note`, …) from the exact same call site on every iteration, so the distance from the caller's frame — and therefore from `&environ`, which lives in the same stack region — to any handler's saved return address is a **fixed delta**, invariant under ASLR (only the absolute base moves, not the in-frame offsets). One `gdb` session pausing inside `create_note` and diffing its return-address slot against the live `&environ` value nails that constant down permanently:

```
ret_slot = environ_val - 0x160
```

### The ROP chain

`create_note` ends in `leave; ret`. Landing our fake data exactly on its saved-RBP/RIP pair hijacks control the instant that call returns — no stack overflow needed, tcache poisoning delivers the "buffer" directly onto the stack.

```python
POP_RDI    = libc.address + 0x10f78b
STACK_FIX  = libc.address + 0x2882f   # bare "ret"
BINSH      = next(libc.search(b"/bin/sh\x00"))
SYSTEM     = libc.sym.system
EXIT       = libc.sym.exit

pad = ret_slot & 0xf                  # fills the fake saved-RBP slot
rop = p64(STACK_FIX) + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) + p64(EXIT)
poison_alloc(0x38, ret_slot, b"A" * pad + rop, read=False)
```

`STACK_FIX` — a lone `ret` gadget — is required, not decorative: `call` always leaves `rsp % 16 == 8` at the callee's entry (SysV ABI), but `leave; ret` here lands `rsp % 16 == 0`, one gadget too early for that convention. `system()`'s own prologue uses SSE instructions that require 16-byte-aligned `rsp`, so without this filler it crashes before it can even reach `execve`.

### Reliability: fgets() eats your poison

Every write in this exploit — poisoned `fd` values, the final ROP chain — goes through the program's `fgets()`. `fgets()` stops at the first `\n` byte, so if ASLR ever hands us an address or gadget offset whose packed bytes happen to contain `0x0a`, the write gets **silently truncated** mid-payload instead of failing loudly. The fix is defensive, not algorithmic: check every packed value before sending it, and if it contains a stray newline, close the connection and retry the whole exploit against a fresh process (fresh ASLR almost certainly won't repeat the same unlucky byte):

```python
def safe(data):
    if b"\n" in data[:-1]:
        raise Retry(f"unlucky ASLR: newline in payload {data!r}")
    return data
```

One more small synchronization wrinkle after the hijack actually fires: a half-consumed menu prompt can eat the first byte or two of whatever we send next. Prefixing the final command with a no-op blank line absorbs that instead of corrupting `cat flag.txt` into `cat lag.txt`.

### Reproduction

```
python3 exploit.py            # local test, against ./Heap_devil + ./libc.so.6
python3 exploit.py remote     # 15.235.202.47:9009, retries up to 20x on bad ASLR
```

Verified live against the challenge instance:

```
[*] heap base : 0x59873a1aa000
[*] libc base : 0x7844c1df4000
[*] environ   : 0x7fff1755ce58
[*] ret slot  : 0x7fff1755ccf8
Note 7 created
LYKNCTF{0utsm4rt3d_th3_h34p_d3v1l}
```

### Tools

* **pwntools** (`ELF`, `process`/`remote`, `p64`/`u64`, manual gadget lookup via `ROP(libc).find_gadget`)
* **WSL/Ubuntu 24.04**, whose system glibc happened to exactly match the shipped `2.39-0ubuntu8.7` — let the whole chain be developed and regression-tested locally, byte-identical to remote, before ever touching the real server
* `gdb` + `/proc/<pid>/mem` — used throughout to verify each leak and each poisoned pointer against ground truth rather than trusting the math
