# httpd

> **Category**: Reversing
>
> **Flag**: `CMO{fUn_w1th_m4g1c_p4ck3t5}`

> `httpd` — ELF 64-bit LSB executable, x86-64, **FreeBSD 14.3**, Go (`go1.17.1`), dynamically linked, **not stripped, with `debug_info`**. _"This file was found on an infected host. Can you figure out what it does?"_

> ⚠️ **Decoy:** The binary is named `httpd` and _does_ serve HTTP, but the HTTP listener is a red herring — every request is answered with `Nothing to see here :{`. The real payload is a background goroutine that never touches the HTTP path.

***

### TL;DR

`httpd` masquerades as a web server. At startup it spawns a goroutine that opens a **libpcap** live capture on interface `re0`, sets a BPF filter of `icmp`, and waits for a **magic ICMP "knock"**. A packet matching all of these conditions:

| Field                        | Frame offset        | Required value (as the binary reads it) |
| ---------------------------- | ------------------- | --------------------------------------- |
| ICMP type                    | `0x22`              | `8` (echo request)                      |
| IP total length              | `0x10` (big-endian) | `0x0020` (32)                           |
| ICMP identifier              | `0x26`              | `0x1337`                                |
| ICMP payload (first 4 bytes) | `0x2a`              | `0xe55fdec6` (magic)                    |

…causes the malware to **derive a 16-byte AES-128 key from the packet's own header bytes**, use that key as **both key and IV**, **AES-128-CBC-decrypt a 32-byte ciphertext baked into `.text`**, and `fmt.Fprintln` the plaintext — the flag.

The key depends only on the ICMP checksum word and the IP `frag/TTL/proto` bytes; everything else is pinned by the trigger. That's a tiny search space, so I reconstructed the exact key-derivation from the disassembly and brute-forced the few unknown bytes **offline** — no FreeBSD host, debugger, or live `re0` interface required.

***

### Approach (how I solved it)

My rule going in: **reverse the sample first, don't brute-force its output blind.** The whole solve is static reversing of the binary, ending in a tiny offline brute over the handful of bytes the disassembly proved were unknown.

#### Tooling

* **Python 3** with [`pyelftools`](https://github.com/eliben/pyelftools) — ELF / Go symbol parsing
* [`capstone`](https://www.capstone-engine.org/) — x86-64 disassembly
* [`pycryptodome`](https://www.pycryptodome.org/) — AES-128-CBC
* _(optional)_ `scapy` — to craft the real magic packet and sanity-check the checksum

(`file`, `nm`, `objdump`, `strings` weren't available on the host, so I did all parsing/disasm from Python — which turned out cleaner anyway for a Go binary.)

***

### 1. Initial Triage

```
$ file httpd
httpd: ELF 64-bit LSB executable, x86-64, version 1 (FreeBSD), dynamically linked,
       interpreter /libexec/ld-elf.so.1, for FreeBSD 14.3, Go BuildID=..., with debug_info, not stripped
```

A **Go 1.17.1** binary, **not stripped**, with **DWARF debug info** — so the Go symbol table is fully usable. It statically links `github.com/google/gopacket` (and `.../gopacket/pcap`): the first strong hint that this "web server" actually sniffs traffic.

Filtering the symbol table for the program's own package leaves a tiny attack surface. I pulled the `main.*` symbols straight out of `.symtab`:

```python
from elftools.elf.elffile import ELFFile
elf = ELFFile(open('httpd','rb'))
for s in elf.get_section_by_name('.symtab').iter_symbols():
    if s.name.startswith('main.'):
        print(s.name, hex(s['st_value']), s['st_size'])
```

```
main.main      0x747dc0  size 453
main.handler   0x747fa0  size 222
main..inittask 0x75cf20
```

Two functions of interest: `main.main` and `main.handler`. Everything else is stdlib / gopacket.

***

### 2. Behavioural Analysis (the HTTP decoy)

I disassembled with capstone, resolving call targets and `rip`-relative string loads against the symbol table:

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
text = elf.get_section_by_name('.text'); tbase = text['sh_addr']; data = text.data()
md = Cs(CS_ARCH_X86, CS_MODE_64)
def dis(addr, size):
    for i in md.disasm(data[addr-tbase:addr-tbase+size], addr):
        print(hex(i.address), i.mnemonic, i.op_str)
dis(0x747dc0, 453)   # main.main
dis(0x747fa0, 222)   # main.handler
```

`main.main` does three things:

1. `fmt.Fprintln` a banner,
2. registers `main.handler` on a `net/http.ServeMux` and calls `net/http.(*Server).ListenAndServe`,
3. **starts a goroutine via `runtime.newproc`** — this is the payload.

`main.handler` is the decoy. The method check and both responses:

```asm
cmp word ptr [rcx], 0x4547      ; 'GE'
jne  not_get
cmp byte ptr [rcx+2], 0x54      ; 'T'
jne  not_get
; GET  -> io.WriteString(w, "Nothing to see here :{")   (22 bytes)
; else -> net/http.Error(w, "Method not allowed", 405)  (18 bytes)
```

So the HTTP service is inert. The `lea` feeding `runtime.newproc` loads a closure whose funcval entry resolves to **`0x748080`** (the code region right after `main.handler`). That goroutine is the malware.

***

### 3. Finding the Goroutine Payload (`0x748080`)

Following the funcval pointer and disassembling from `0x748080`, the opening sequence sets up a sniffer (`call` targets resolved via the symbol table):

```asm
; pcap.OpenLive("re0", 1600, true, BlockForever)
lea  rax, ["re0"]                ; iface
mov  [rsp+8], 3                  ; len("re0")
mov  [rsp+0x10], 0x640           ; snaplen = 1600
mov  [rsp+0x14], 1               ; promiscuous = true
mov  [rsp+0x18], 0xffffffffff676980   ; timeout = BlockForever
call github.com/google/gopacket/pcap.OpenLive

; handle.SetBPFFilter("icmp")
lea  rcx, ["icmp"]
mov  [rsp+0x10], 4
call pcap.(*Handle).SetBPFFilter

call pcap.(*Handle).pcapDatalink
call gopacket.(*PacketSource).Packets   ; returns a channel
```

It then enters a `for range packets` loop (`runtime.chanrecv2` on the packet channel) and, for each packet, calls `Packet.Data()` (`call rax`) to get the raw frame bytes, bounds-checks the length, and inspects fixed offsets into the Ethernet/IP/ICMP frame.

***

### 4. The Trigger Conditions (the "magic packet")

The per-packet gate is a chain of compares against raw frame offsets. With Ethernet(14) + IP(20) + ICMP the offsets line up exactly:

```asm
cmp word  ptr [rdx+0x26], 0x1337       ; ICMP identifier == 0x1337
jne  next
movzx ebx, word ptr [rdx+0x10]         ; IP total length
rol  bx, 8                             ; -> host order
cmp  bx, 0x20                          ; == 32
jne  next
cmp  dword ptr [rdx+0x2a], 0xe55fdec6  ; ICMP payload[0:4] == magic
jne  next
cmp  byte  ptr [rdx+0x22], 8           ; ICMP type == 8 (echo request)
jne  next
```

So the trigger is a 32-byte IP packet: an ICMP **echo request**, id `0x1337`, carrying a 4-byte payload `0xe55fdec6`.

> **Byte-order gotcha.** These are x86 _little-endian_ reads, so the values the binary compares (`0x1337`, `0xe55fdec6`) are **byte-swapped on the wire**: the identifier bytes are `37 13` and the payload bytes are `c6 de 5f e5`. This matters if you actually craft the packet with scapy: you set `ICMP(id=0x3713)` and `payload = b"\xc6\xde\x5f\xe5"`, and the malware's LE reads then see `0x1337` / `0xe55fdec6`. (It does **not** affect the key/flag, because the key derivation in §5 reads the same raw frame bytes.)

***

### 5. The Key Derivation

When a packet matches, the code `makeslice`s a 16-byte buffer and fills it from packet header bytes, with two small XOR/byte-swap twists. Translating the disassembly (`0x74827e`–`0x748459`) byte-for-byte:

Let `W` = the 16-bit little-endian word read at frame offset `0x24` (the ICMP **checksum** field), and `IP[0x14:0x18]` = the four IP-header bytes at offset `0x14` (`flags/frag(2) · TTL(1) · proto(1)`). The 16-byte key is:

```
key[0:2]   = big-endian( 0xe55f ^ W )          # high word of magic XOR checksum, byte-swapped
key[2:6]   = IP[0x14:0x18]                      # frag(2) + TTL(1) + proto(1), copied verbatim
key[6:8]   = W                                  # checksum word, little-endian
key[8:12]  = 0xe55fdec6  (LE: c6 de 5f e5)      # the magic constant
key[12:14] = 0x1337      (LE: 37 13)            # the ICMP id
key[14:16] = big-endian( (W ^ 0xdec6) & 0xffff) # low word of magic XOR checksum, byte-swapped
```

The same 16-byte buffer is then passed as **both** the AES key **and** the CBC IV.

Crucially, **only two things vary**: the checksum word `W` (16 bits) and the IP `frag/TTL/proto` bytes — everything else is fixed by the magic constants. That makes the key space trivially small.

***

### 6. The Embedded Ciphertext & AES-128-CBC Decrypt

Right after building the key, the goroutine constructs the ciphertext from four immediate `movabs` stores, then runs standard Go crypto:

```asm
movabs rcx, 0xc07edfb429a5f151 ; mov [obj+0x00], rcx
movabs rcx, 0xb34e3d248f2f3b2a ; mov [obj+0x08], rcx
movabs rcx, 0x8cdd9c0bcfb0ed5a ; mov [obj+0x10], rcx
movabs rcx, 0x0c64c43e9b0ee6cd ; mov [obj+0x18], rcx
...
call crypto/aes.NewCipher          ; key length 0x10 -> AES-128
call crypto/cipher.NewCBCDecrypter ; iv = same key buffer
call <blockmode>.CryptBlocks       ; decrypt 32 bytes in place
call runtime.slicebytetostring
call fmt.Fprintln                  ; print plaintext (the flag)
```

The 32-byte ciphertext (qwords stored little-endian, in order):

```
51 f1 a5 29 b4 df 7e c0  2a 3b 2f 8f 24 3d 4e b3
5a ed b0 cf 0b 9c dd 8c  cd e6 0e 9b 3e c4 64 0c
```

So the entire secret is **`AES-128-CBC-decrypt(ct, key=K, iv=K)`** where `K` is derived from the magic packet as in §5.

***

### 7. Recovering the Key (offline brute force)

I never see the attacker's packet, but I don't need it. The unknowns are:

* `W` — the ICMP checksum word: **16 bits**.
* `IP[0x14:0x18]` — for any realistic crafted packet: `proto = 0x01` (ICMP), `flags/frag` ∈ `{0x0000, 0x4000(DF)}`, `TTL` ∈ a handful of common values (`64, 128, 255, …`).

I reconstructed the §5 derivation exactly, swept `W` over `0..0xffff` for each plausible IP tuple, AES-CBC-decrypted the embedded ciphertext, and stopped when the plaintext started with `CMO{`. This is the script I actually ran:

```python
import struct
from Crypto.Cipher import AES

# 32-byte embedded ciphertext (4 LE qwords, in store order)
qs = [0xc07edfb429a5f151, 0xb34e3d248f2f3b2a, 0x8cdd9c0bcfb0ed5a, 0x0c64c43e9b0ee6cd]
CT = b''.join(struct.pack('<Q', q) for q in qs)
MAGIC, ID = 0xe55fdec6, 0x1337

def build_key(W, b14, b15, ttl, proto=0x01):
    v = (0xe55f ^ W) & 0xffff           # key[0:2]  = big-endian(v)
    u = (W ^ 0xdec6) & 0xffff           # key[14:16]= big-endian(u)
    k = bytearray(16)
    k[0], k[1]   = (v >> 8) & 0xff, v & 0xff
    k[2:6]       = bytes([b14, b15, ttl, proto])
    k[6], k[7]   = W & 0xff, (W >> 8) & 0xff
    k[8:12]      = struct.pack('<I', MAGIC)
    k[12], k[13] = ID & 0xff, (ID >> 8) & 0xff
    k[14], k[15] = (u >> 8) & 0xff, u & 0xff
    return bytes(k)

for frag in (0x0000, 0x4000):
    for ttl in (64, 128, 255, 63, 127):
        for W in range(0x10000):
            k  = build_key(W, (frag >> 8) & 0xff, frag & 0xff, ttl)
            pt = AES.new(k, AES.MODE_CBC, iv=k).decrypt(CT)
            if pt[:4] == b'CMO{':
                pad = pt[-1]
                print('frag=%04x ttl=%d W=%04x' % (frag, ttl, W))
                print('key/iv =', k.hex())
                print('FLAG   =', pt[:-pad].decode())
```

Hit on the first realistic packet shape (`DF`, TTL 64, proto ICMP):

```
frag=4000 ttl=64 W=279a
key/iv = c2c5400040019a27c6de5fe53713f95c
FLAG   = CMO{fUn_w1th_m4g1c_p4ck3t5}
```

The raw plaintext is `CMO{fUn_w1th_m4g1c_p4ck3t5}\x05\x05\x05\x05\x05` — valid **PKCS#7** padding (`pad=5`), which corroborates the AES-CBC interpretation.

***

### 8. End-to-end sanity check (optional, scapy)

To prove the recovered `W=0x279a` corresponds to a _real_ checksum-valid packet, I crafted the exact magic knock and read back the checksum scapy computed. Searching the ICMP sequence field shows the matching packet is `seq=1` (checksum `0x9a27` → `W=0x279a`):

```python
from scapy.all import IP, ICMP, raw
for seq in range(8):
    f = raw(IP(flags='DF', ttl=64)/ICMP(type=8, id=0x3713, seq=seq)/b'\xc6\xde\x5f\xe5')
    W = f[0x16] | (f[0x17] << 8)        # checksum word (IP-only frame: 0x24 - 14)
    print('seq=%d cksum_wire=%02x%02x W=0x%04x' % (seq, f[0x16], f[0x17], W))
# seq=1 -> cksum_wire=9a27 W=0x279a  -> matches the brute-forced key
```

So the attacker's trigger was: **ICMP echo-request, `id` wire-bytes `37 13`, `seq=1`, payload `c6 de 5f e5`, IP total length 32 (DF, TTL 64)** — feeding it to a running `httpd` prints the flag.

***

### 9. Reproduction Steps

```bash
unzip httpd_handout.zip                 # -> httpd, README.md
pip install pyelftools capstone pycryptodome
# 1) parse symbols + disassemble main.main / 0x748080 (sections 1-6)
# 2) run the brute-force in section 7  ->  CMO{fUn_w1th_m4g1c_p4ck3t5}
```

To exercise the malware for real (FreeBSD with a `re0` interface): run `./httpd` as root, then from another host send the §8 packet; `httpd` prints the flag to its stdout.

***

### Appendix: Captured Data

**Flag**

```
CMO{fUn_w1th_m4g1c_p4ck3t5}
```

**Embedded AES-128-CBC ciphertext (32 bytes)**

```
51 f1 a5 29 b4 df 7e c0 2a 3b 2f 8f 24 3d 4e b3
5a ed b0 cf 0b 9c dd 8c cd e6 0e 9b 3e c4 64 0c
```

**Recovered key == IV**

```
c2 c5 40 00 40 01 9a 27 c6 de 5f e5 37 13 f9 5c
```

**Magic packet (on the wire)**

```
ICMP echo-request  type=8  id-bytes=37 13  seq=1  payload=c6 de 5f e5
IP total length=32, flags=DF, TTL=64, proto=1
```

#### Key addresses

| Address               | Symbol / meaning                                                           |
| --------------------- | -------------------------------------------------------------------------- |
| `0x747dc0`            | `main.main` (banner + HTTP setup + `newproc`)                              |
| `0x747fa0`            | `main.handler` (HTTP decoy: `Nothing to see here :{`)                      |
| `0x748080`            | goroutine payload — `pcap.OpenLive("re0", 1600, promisc, BlockForever)`    |
| `0x748123`            | `SetBPFFilter("icmp")`                                                     |
| `0x74845e`–`0x74849e` | magic-packet trigger compares (`0x1337`, len `0x20`, `0xe55fdec6`, type 8) |
| `0x74827e`–`0x748459` | 16-byte key derivation from packet bytes                                   |
| `0x7484d2`–`0x748505` | 32-byte ciphertext `movabs` immediates                                     |
| `0x748525`            | `crypto/aes.NewCipher` (AES-128)                                           |
| `0x7485a5`            | `crypto/cipher.NewCBCDecrypter` (iv == key)                                |
| `0x748696`            | `fmt.Fprintln` (prints the flag)                                           |

#### Constants

| Constant     | Role                                                             |
| ------------ | ---------------------------------------------------------------- |
| `0xe55fdec6` | ICMP payload magic (wire `c6 de 5f e5`); also key bytes `[8:12]` |
| `0x1337`     | ICMP identifier (wire `37 13`); also key bytes `[12:14]`         |
| `0x0020`     | required IP total length                                         |
| `8`          | required ICMP type (echo request)                                |
