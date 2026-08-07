# Zip, Zip, Hooray!

> **Category**: Misc
>
> **Flag**: `bronco{i_h4te_f1l3_c0mpr3ssi0n}`

> I was trying to compress my files and my script got a little carried away... Can you help me find my original file?

***

### Initial Reconnaissance

#### File Identification

The challenge provides a single file: `challenge.zip` (469,472 bytes / \~459 KB).

```bash
file challenge.zip
# challenge.zip: gzip compressed data, original size modulo 2^32 481280
```

**Key finding:** Despite the `.zip` extension, this is actually a **gzip** archive. This is the first trick — the file extension is misleading.

#### Examining the Contents

```bash
7z l challenge.zip
```

```
7-Zip 23.01 (x64)

Path = challenge.zip
Open WARNING: Cannot open the file as [zip] archive
Type = gzip
Headers Size = 21

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2026-02-28 09:39:52 .....       481280       469472  layer1.tar
------------------- ----- ------------ ------------  ------------------------
2026-02-28 09:39:52             481280       469472  1 files
```

The gzip contains a single file: `layer1.tar`.

#### Deeper Inspection with Python

```python
import gzip, tarfile, io

with gzip.open('challenge.zip', 'rb') as f:
    data = f.read()

tar = tarfile.open(fileobj=io.BytesIO(data))
for m in tar.getmembers():
    print(f'{m.name} | size={m.size} | type={m.type}')
tar.close()
```

```
layer2.bz2 | size=469180 | type=0
```

The tar contains `layer2.bz2` (bzip2 compressed data).

#### Hex Dump — Confirming Gzip

```
00000000: 1f8b 0808 7855 a269 02ff 6c61 7965 7231  ....xU.i..layer1
00000010: 2e74 6172 00ec ba67 5453 d1d7 3e88 5214  .tar...gTS..>.R.
```

* `1f8b` — Gzip magic bytes
* `08` — Deflate compression method
* `08` — FNAME flag (filename stored in header)
* `layer1.tar` — The stored filename (this is the "first file" the hint refers to)

***

### Understanding the Archive Stack

After extracting a few layers, a clear repeating pattern emerges:

```
challenge.zip (gzip)
  └── layer1.tar (tar)
        └── layer2.bz2 (bzip2)
              └── layer2 (7z, password-protected)
                    └── layer4.zip (zip)
                          └── layer5.tar.gz (gzip)
                                └── layer5.tar (tar)
                                      └── layer6.bz2 (bzip2)
                                            └── layer6 (7z, password-protected)
                                                  └── layer8.zip (zip)
                                                        └── ...
```

**The repeating cycle is:**

1. **Gzip** → extracts to **Tar**
2. **Tar** → contains **Bzip2**
3. **Bzip2** → decompresses to **7z** (password-protected)
4. **7z** → extracts **Zip**
5. **Zip** → contains **Gzip** (back to step 1)

Each 7z archive is password-protected, and each cycle reduces the file size slightly (\~3 KB per cycle).

***

### Cracking the 7z Password

#### The Hint

> The password is the name of the first file inside `C:\Users\moriarty\Downloads\challenge.zip`

#### Analysis

The "first file inside" `challenge.zip` depends on how you interpret it:

* The gzip header stores the filename as `layer1.tar`
* The tar archive contains `layer2.bz2`

However, the actual working password for each 7z archive is **the name of the file contained within that specific 7z archive**. For example:

| 7z Archive | Contains      | Password      |
| ---------- | ------------- | ------------- |
| `layer2`   | `layer4.zip`  | `layer4.zip`  |
| `layer6`   | `layer8.zip`  | `layer8.zip`  |
| `layer10`  | `layer12.zip` | `layer12.zip` |
| ...        | ...           | ...           |

The pattern: the **password equals the inner filename**.

#### Verification

```python
import py7zr

with py7zr.SevenZipFile('layer2', mode='r', password='layer4.zip') as z:
    print(f'Files: {z.getnames()}')
    z.extractall(path='out')
    print('Extraction successful!')
```

```
Files: ['layer4.zip']
Extraction successful!
```

***

### Automated Extraction Script

The challenge has **1001 nested layers**. Manual extraction is impossible — here's the full Python automation:

```python
#!/usr/bin/env python3
"""
Zip, Zip, Hooray! — Automated Nested Archive Extractor
Extracts 1001 layers of nested compression to find the flag.
"""

import py7zr
import zipfile
import gzip
import tarfile
import io
import os
import subprocess
import sys
import shutil


def extract_nested(archive_path, max_layers=1100):
    """
    Recursively extract nested archives until we hit the innermost file.
    
    Archive cycle:
      gzip -> tar -> bz2 -> 7z (pw) -> zip -> gzip -> tar -> bz2 -> 7z (pw) -> ...
    
    7z password rule: the password is the name of the file inside the 7z archive.
    """
    workdir = '/tmp/opencode/challenge/automated'
    os.makedirs(workdir, exist_ok=True)
    
    current = archive_path
    layer = 0
    
    while True:
        layer += 1
        
        # Read magic bytes to identify file type
        with open(current, 'rb') as f:
            magic = f.read(6)
        
        sz = os.path.getsize(current)
        
        # ── Gzip ──────────────────────────────────────────────
        if magic[:2] == b'\x1f\x8b':
            next_file = os.path.join(workdir, f'layer_{layer}')
            with gzip.open(current, 'rb') as gf:
                data = gf.read()
            tar = tarfile.open(fileobj=io.BytesIO(data))
            for member in tar.getmembers():
                if member.isfile():
                    with tar.extractfile(member) as ef:
                        content = ef.read()
                    with open(next_file, 'wb') as out:
                        out.write(content)
                    current = next_file
                    break
            tar.close()
        
        # ── Bzip2 ─────────────────────────────────────────────
        elif magic[:3] == b'BZh':
            next_file = os.path.join(workdir, f'layer_{layer}')
            subprocess.run(
                ['bunzip2', '-k', '-f', '-c', current],
                stdout=open(next_file, 'wb'),
                stderr=subprocess.DEVNULL
            )
            current = next_file
        
        # ── 7-Zip (password-protected) ────────────────────────
        elif magic == b'7z\xbc\xaf\x27\x1c':
            # Password = the name of the file inside the archive
            with py7zr.SevenZipFile(current, mode='r', password='x') as z:
                names = z.getnames()
            inner_name = names[0]
            
            out_dir = os.path.join(workdir, f'layer_{layer}_dir')
            os.makedirs(out_dir, exist_ok=True)
            with py7zr.SevenZipFile(current, mode='r', password=inner_name) as z:
                z.extractall(path=out_dir)
            current = os.path.join(out_dir, inner_name)
        
        # ── Zip ───────────────────────────────────────────────
        elif magic[:2] == b'PK':
            with zipfile.ZipFile(current) as zf:
                names = zf.namelist()
                out_dir = os.path.join(workdir, f'layer_{layer}_dir')
                os.makedirs(out_dir, exist_ok=True)
                zf.extractall(out_dir)
                current = os.path.join(out_dir, names[0])
        
        # ── Tar ───────────────────────────────────────────────
        elif magic[:5] == b'ustar' or magic[:6] == b'././@P':
            next_file = os.path.join(workdir, f'layer_{layer}')
            tar = tarfile.open(current)
            for member in tar.getmembers():
                if member.isfile():
                    with tar.extractfile(member) as ef:
                        content = ef.read()
                    with open(next_file, 'wb') as out:
                        out.write(content)
                    current = next_file
                    break
            tar.close()
        
        # ── Unknown / Final file ──────────────────────────────
        else:
            with open(current, 'rb') as f:
                content = f.read(2000)
            
            print(f'\n{"="*60}')
            print(f'  Layer {layer}: INNERMOST FILE REACHED')
            print(f'{"="*60}')
            print(f'  File:   {current}')
            print(f'  Size:   {sz} bytes')
            print(f'  Magic:  {content[:20].hex()}')
            print(f'{"="*60}')
            
            text = content.decode('utf-8', errors='replace')
            print(f'\n  Content:\n  {text[:500]}')
            
            # Save the flag file
            shutil.copy2(current, os.path.join(workdir, 'flag.txt'))
            return text, layer
        
        # Progress indicator
        if layer % 100 == 0:
            print(f'  ...layer {layer}, size: {sz} bytes', file=sys.stderr)
        
        if layer > max_layers:
            print(f'Stopped at layer {layer} (max reached)')
            return None, layer


if __name__ == '__main__':
    archive = '/path/to/challenge.zip'
    content, total_layers = extract_nested(archive)
    print(f'\nTotal layers extracted: {total_layers}')
```

#### Running the Script

```bash
# Install dependencies
pip install py7zr

# Run extraction
python3 solve.py
```

#### Output

```
  ...layer 100, size: 392292 bytes
  ...layer 200, size: 323281 bytes
  ...layer 300, size: 262773 bytes
  ...layer 400, size: 209122 bytes
  ...layer 500, size: 161943 bytes
  ...layer 600, size: 120197 bytes
  ...layer 700, size: 83856 bytes
  ...layer 800, size: 52331 bytes
  ...layer 900, size: 24592 bytes
  ...layer 1000, size: 147 bytes

============================================================
  Layer 1001: INNERMOST FILE REACHED
============================================================
  File:   /tmp/.../layer_1000_dir/flag.txt
  Size:   31 bytes
  Magic:  62726f6e636f7b695f683474655f66316c335f63
============================================================

  Content:
  bronco{i_h4te_f1l3_c0mpr3ssi0n}

Total layers extracted: 1001
```

***

### Flag

```
bronco{i_h4te_f1l3_c0mpr3ssi0n}
```

***

### Tools Used

| Tool               | Purpose                                        |
| ------------------ | ---------------------------------------------- |
| `7z` / `7za`       | Listing and extracting archives                |
| `file`             | Identifying file types by magic bytes          |
| `xxd`              | Hex dumping to inspect raw bytes               |
| `bunzip2`          | Decompressing bzip2 files                      |
| `tar`              | Extracting tar archives                        |
| Python 3           | Scripting the automated extraction             |
| `py7zr`            | Python library for 7z extraction with password |
| `gzip` (Python)    | Decompressing gzip streams                     |
| `tarfile` (Python) | Parsing tar archives in memory                 |
| `zipfile` (Python) | Extracting zip archives                        |

***

### Reasoning & Methodology

#### Step 1: Identify the File Type

The `.zip` extension was a red herring. Running `file` on the archive revealed it was actually **gzip**, not zip. The hex dump confirmed this with the `1f8b` magic bytes.

#### Step 2: Understand the Nesting

After extracting the first few layers manually, I noticed a repeating pattern:

```
gzip → tar → bz2 → 7z → zip → gzip → tar → bz2 → 7z → zip → ...
```

This is a **4-format cycle** that repeats. Each iteration reduces the file size by approximately 3 KB (overhead of the compression headers).

#### Step 3: Solve the Password Problem

The hint mentioned the password was "the name of the first file inside challenge.zip". After trying `layer1.tar` (the gzip header filename) and `layer2.bz2` (the tar entry), I discovered the actual pattern:

**Each 7z archive's password is the name of the file it contains.**

This makes sense if you think of it as a self-referential puzzle — the password to unlock a layer is the name of the next layer inside it.

#### Step 4: Automate

With 1001 layers to extract, manual extraction was impossible. I wrote a Python script that:

1. Reads the first 6 bytes (magic bytes) to identify the file type
2. Dispatches to the appropriate extraction method
3. Follows the extracted file to the next layer
4. Repeats until it reaches the innermost file

#### Step 5: Extract the Flag

After 1001 iterations, the innermost file was `flag.txt` (31 bytes), containing the flag.

***

### Key Takeaways

1. **File extensions lie** — Always check magic bytes, not just file extensions
2. **Nested archives can be automated** — Pattern recognition + scripting defeats repetitive challenges
3. **Password patterns matter** — In CTF challenges, password logic often follows a pattern (self-referential, sequential, derived from metadata)
4. **Compression overhead is cumulative** — Each layer adds \~3-6 KB of overhead, which is how we can estimate the number of layers before extraction

***

### Difficulty Rating

The main challenge is recognizing the pattern and writing efficient automation. The actual crypto (7z AES) is irrelevant since the password logic is deterministic. The file is \~460 KB but contains 1001 nested layers — an impressive (and annoying) feat of recursive compression.
