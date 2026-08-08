# i hate this app revenge

> **Category:** Reverse Engineering (Rust / Tauri desktop app + crypto)
>
> **Flag:** `LYKNCTF{alolanvulpix}`

> This app is bullying me again... I'm going to download their entire image gallery. Instead of getting actual images, all I got was a bunch of weird encrypted text. Decrypt the file, recover the image, and identify the character shown in it. FLAG FORMAT: `LYKNCTF{character_name}` (lowercase, no spaces).

### Files

* `726471288_..._n.enc.bin` — 33112 bytes, the encrypted image
* `fuoverflow_learning (1).rar` → `fuoverflow_learning.exe`
  * a **Rust** binary (Tauri desktop app; `rustc` appears hundreds of times in strings)

### TL;DR

The `.enc.bin` is a "FixedEnvelope": **12-byte nonce + AES‑256‑CTR ciphertext**.

* Reversing the Rust binary reveals `src\commands\decrypt.rs`, a `FixedEnvelope` struct, and two env-var-with-default secrets (`FIXED_ENCRYPTION_KEY`, `FUO_PASS_SECRET`).
* The default keys are stored as one contiguous ASCII blob in `.rdata`: `3qyJU3Z6IXlfpr2CErOHH76ugQcAoWzYH}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M`
  * `FUO_PASS_SECRET` = bytes\[0:32] = `3qyJU3Z6IXlfpr2CErOHH76ugQcAoWzY`
  * `FIXED_ENCRYPTION_KEY` = bytes\[32:64] = `H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M`
* `decrypt_fixed` (`0x1401fa2b0`) is **AES‑256‑CTR**, no GCM tag. The 16-byte counter block for block _i_ is: `file[0:8] ++ big_endian_u64(7 + i)`, where the file starts with the 12-byte nonce `00 11 22 33 44 55 66 77 00 00 00 07`.
* Decrypt with `FIXED_ENCRYPTION_KEY` → a valid JPEG (`FF D8 FF E0 ... "JFIF"`).
* The image is a white, snow-dwelling fox Pokémon with a curled tail = **Alolan Vulpix**.

Run `recover.py` to reproduce the JPEG and see the header.

### Reasoning / Steps

#### 1. Identify the encrypted file layout

```
00000000: 0011 2233 4455 6677 0000 0007 c7b9 63f6  .."3DUfw......c.
```

The first 12 bytes `00 11 22 33 44 55 66 77 00 00 00 07` look like a fixed nonce (8-byte pattern + 4-byte counter). File is 33112 bytes → 12 nonce + \~33100 ciphertext.

#### 2. Fingerprint the app

The 17 MB `fuoverflow_learning.exe` is a **Rust** binary (`rustc` x362 in strings), a **Tauri** app (`__TAURI_INVOKE_KEY__`, `index.html`, CSP header). Its own source paths show up:

```
src\commands\decrypt.rs
src\commands\http_proxy.rs
struct FixedEnvelope  ... encrypted_fixed iv data
```

and crucially the RustCrypto crates `aes-0.8.4` + `cipher-0.4.4` (the combo used by AES-CTR / AES-GCM), not just ring/rustls (which is only the HTTPS client).

#### 3. Find the keys

Strings near `decrypt.rs` reveal env-var names with embedded defaults:

```
FUO_PASS_SECRET   fuo-node-  ...
FIXED_ENCRYPTION_KEY
"Invalid IV length: expected 12, got"
"Decryption failed - invalid key or corrupted data"
```

Disassembling the env-var getters shows they return a default 32-byte value when the env var is unset. The defaults are produced by two tiny functions that `movaps` a contiguous ASCII blob at VA `0x140c5fdf0`:

```
3qyJU3Z6IXlfpr2CErOHH76ugQcAoWzYH}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9Mault_window_icon
^--------------------------------^--------------------------------^
   FUO_PASS_SECRET (0:32)           FIXED_ENCRYPTION_KEY (32:64)     ("def")ault_...
```

#### 4. Recover the exact cipher (AES-256-CTR)

`decrypt_fixed` (`0x1401fa2b0`) does **not** verify a GCM tag; it is a pure CTR keystream XOR. From the disassembly:

* `nonce = file[0:12]` (`"expected 12"`).
*   The counter block is assembled as `r12 = file[0:8]` (raw 8 bytes) and `low8 = bswap64(r13 + i)` where `r13 = bswap64(u32_le(file[8:12]))`. Working the byte order through, this is simply:

    ```
    counter_block[i] = file[0:8]  ++  (7 + i).to_bytes(8, 'big')
    ```
* Key = `FIXED_ENCRYPTION_KEY` (32 bytes → AES-256).

#### 5. Decrypt → JPEG → identify

Decrypting yields `FF D8 FF E0 00 10 "JFIF" ... FF D9` — a clean JPEG. Rendering it shows a white/ice fox Pokémon with a fluffy curled tail and a tuft on its head in a snowy scene: **Alolan Vulpix**.

### Flag

```
LYKNCTF{alolanvulpix}
```

### Tools

* WinRAR (extract)
* Python + Capstone (disassemble `decrypt_fixed`, read the key blob from `.rdata`)
* `pycryptodome` (`Crypto.Cipher.AES` ECB, to build the CTR keystream)
* Any image viewer (identify the character)

### Files in this folder

* `recover.py` — self-contained: reads the key blob from the exe, decrypts the `.enc.bin` with AES-256-CTR, writes `recovered.jpg`.
