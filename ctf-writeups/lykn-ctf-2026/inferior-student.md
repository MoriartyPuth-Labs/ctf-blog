# inferior student

>
>
> **Category:** Reversing
>
> **Flag:**`LYKNCTF{Im_At_The_PayPhone_Tryin_To_Home_Allof_My_change_1_Spent_0n_u_Where_have_ThE_T1m3S_G0n3_B4bY_Its_Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}`

### Files

* `chall.exe` — PyInstaller build (Python 3.12)
* `challl.py` — 1.2 MB of unicode-obfuscated Python with heavy anti-debug

### TL;DR

`challl.py` is a matryoshka: each layer decrypts the next with **ChaCha20**, keyed by `sha256(d1 + bytes([d2 ^ eps]))[:32]`, then **LZMA**-decompresses to a Python 3.12 code object and `exec`s it. `eps` is an **anti-debug accumulator that equals 0 in a clean run** and becomes non-zero the instant any tracer/timing anomaly/tampering is detected — a wrong `eps` gives a wrong key, the SHA-256 integrity check fails, and the program silently does nothing ("Nothing Stay").

**Winning idea:** the program integrity-checks `exec`/`marshal`/`time`, so those can't be hooked — but wrapping the **crypto library** is safe. So:

1. Wrap `Crypto.Cipher.ChaCha20.new` and steal the encrypted chunk table `__68a3ce74cb6bc2b44970e0c__` = list of `(d1: bytes, d2: int, nonce: bytes, ct: bytes, expected_sha256: bytes)`.
2. **Brute `eps` offline** — it's a single byte (0..255). For each chunk find the `eps` where `sha256(ChaCha20(sha256(d1+bytes([d2^eps]))[:32], nonce).decrypt(ct)) == expected`. It is `eps = 0` for every chunk.
3. Decrypt+LZMA the chunks → Python 3.12 code objects (disguised with `co_filename = ...asyncio/events.py`). The real program is a nested packer of the same shape.
4.  The **innermost layer is a flag checker**: it prints `flag:` , reads input, then does `Cipher(ChaCha20(key, nonce)).encryptor().update(processed_input) == target`. ChaCha20 is a stream cipher (encrypt == decrypt), and the key/nonce are **fixed**, so:

    ```
    flag = ChaCha20(key, nonce).decrypt(target)
    ```
5. Capture the checker's three locals (`var_ac20c8330b5c6c16` = 32-byte key, `var_68f8ea7d3b0bd13e` = 16-byte nonce, `var_2229d99752634209` = 145-byte target) at the `input()` call, and decrypt the target directly. Done.

### Reasoning / Steps

#### 1. Recon

`challl.py` opens with unicode-named imports and anti-debug: `sys.gettrace()`, `sys.monitoring`, ptrace/`NtQueryInformationProcess` debug-port checks, `/proc/self/status` TracerPid, and a timing loop — all XORing into an accumulator `εиδкנаш` (call it `eps`). It ends by spawning threads that call one worker `π…(index)`, then `exec`ing a code object that was decrypted from a big blob.

Any obvious instrumentation makes the program print nothing:

* Hooking `builtins.exec` / `marshal.loads` / freezing `time` → **detected** (the integrity/timing checks flip `eps`, key is wrong, layer bails silently).
* Even a plain slowdown trips a `perf_counter` check.
* Only wrapping the **crypto library** functions (`ChaCha20.new`, `AES.new`) is low-overhead and undetected — the anti-debug never inspects them.

#### 2. The worker function (recovered by disassembling a captured code object)

```python
def worker(index):
    d1, d2, nonce, ct, expected = TABLE[index]      # TABLE = __68a3ce74cb6bc2b44970e0c__
    key = sha256(d1 + bytes([d2 ^ eps]))[:32]        # eps == 0 in a clean run
    pt  = ChaCha20(key=key, nonce=nonce).decrypt(ct)
    if sha256(pt).digest() != expected:              # integrity gate
        return                                        # "Nothing Stay"
    payload = lzma.decompress(pt)                     # Python 3.12 marshalled code object
    exec(compile-ish(payload), ...)                   # run next layer; source is wiped
```

#### 3. Steal the table, brute `eps`, decrypt the layers

* `01_grab_table.py` wraps `ChaCha20.new`, reads `__68a3ce74cb6bc2b44970e0c__` from the caller's globals, pickles it.
* `02_brute_eps.py` brute-forces `eps` (finds 0) per chunk and dumps each decompressed code object. Chunk index 3 is the big (\~1.7 MB) main payload; it's another packer of the same form, ultimately reaching a flag checker.

#### 4. The checker → decrypt the flag

Under the real (Python 3.12) runtime, the innermost checker `input()`s at the prompt `flag:` , then uses the `cryptography` library's ChaCha20 with a fixed key + nonce and compares to a stored target ciphertext. Because ChaCha20 is a stream cipher and the key/nonce are constants, the answer is simply the decryption of that target.

`03_capture_and_decrypt_flag.py`:

* wraps `ChaCha20.new` to _fix_ `eps` at the boundary (bruting it per-chunk so every layer runs correctly, regardless of the anti-debug state), and
* wraps `builtins.input` so that, at the moment the checker asks for the flag, it dumps the checker frame's `var_*` locals, then computes `flag = ChaCha20(var_ac20c8330b5c6c16, var_68f8ea7d3b0bd13e).decrypt(var_2229d99752634209)`.

Result:

```
b'LYKNCTF{Im_At_The_PayPhone_Tryin_To_Home_Allof_My_change_1_Spent_0n_u_Where_have_ThE_T1m3S_G0n3_B4bY_Its_Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}'
```

### Flag

```
LYKNCTF{Im_At_The_PayPhone_Tryin_To_Home_Allof_My_change_1_Spent_0n_u_Where_have_ThE_T1m3S_G0n3_B4bY_Its_Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}
```

### Tools

* **Python 3.12** (must match the packer's bytecode version — deeper layers are 3.12 marshalled code objects)
* `pycryptodome` (`Crypto.Cipher.ChaCha20`) — to wrap the crypto boundary and brute `eps`
* `cryptography` (`hazmat...ChaCha20`) — used by the innermost checker (and by us to decrypt the target)
* `hashlib`, `lzma`

### Files in this folder

* `01_grab_table.py` — steal the chunk table (`table.pkl`)
* `02_brute_eps.py` — brute `eps` (=0), decrypt+LZMA each layer
* `03_capture_and_decrypt_flag.py` — run to completion with `eps` fixed at the crypto boundary; capture the checker vars at `input()`; print the flag

> Install deps into 3.12: `py -3.12 -m pip install pycryptodome cryptography`
