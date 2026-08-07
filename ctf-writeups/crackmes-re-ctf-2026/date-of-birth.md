# date of birth

> **Category**: Reversing
>
> **Flag**: `6/29/1898`&#x20;

> **"Enter your date of birth to verify your identity."**
>
> _"Welcome to Discard App -- a new way to discard your personal information!"_
>
> **File:** `date_of_birth` (ELF64, dynamically linked, stripped — anti-debug via SIGSTOP)

**Solution format:** `MM/DD/YYYY` — any date satisfying all three conditions below simultaneously:

```
Condition 1: (current_time - birth_date) days component  ∈ {30, 31}
Condition 2: (current_time - birth_date) months component = 11 (December in epoch)
Condition 3: (current_time - birth_date) years component ≡ 127  (mod 256)
```

**Example valid inputs (as of June 28, 2026):**

```
6/29/1898
6/29/1642
6/29/1386
6/29/1130
6/29/874
6/29/618
6/29/362
6/29/106
```

> These values are date-dependent. Run `keygen.py` to generate valid inputs for today.

#### File Verification

|                       |                                                                    |
| --------------------- | ------------------------------------------------------------------ |
| **Binary filename**   | `date_of_birth`                                                    |
| **Format**            | ELF 64-bit LSB, dynamically linked, stripped                       |
| **Anti-debug**        | Sends `SIGSTOP` to itself — GDB breakpoints fail at entry          |
| **keygen.py SHA-256** | `8172405b3e2da00eb2e35efb8ded672e7b29dc0452c1f4360d1c3b5c5af93c72` |
| **keygen.py MD5**     | `1c0b13aeabccff1e0ee93b928193ff8c`                                 |
| **Source**            | https://crackmes.one/crackme/5f855fe333c5d424269a14ed              |

> The binary must be downloaded from crackmes.one. It is not bundled in this repository.

```bash
chmod +x date_of_birth
```

***

### Table of Contents

1. TL;DR
2. Tooling
3. Initial Triage
4. Behavioural Analysis
5. Anti-Debug — SIGSTOP
6. Finding main via Entry Point
7. The Input — scanf with Date Format
8. Parsing the Date — strptime and mktime
9. Computing the Difference — time() and localtime()
10. The Three-Branch Check
11. The Winning Condition — Signed Byte Overflow
12. The Keygen — Computing Valid Dates
13. Full Solver (PoC)
14. Reproduction Steps
15. Confirming on the Binary
16. Appendix: Key Addresses & Structures

***

### TL;DR

The binary asks for a date of birth in `MM/DD/YYYY` format. It parses it with `strptime`, converts to a Unix timestamp with `mktime`, subtracts it from `time(NULL)` to get the number of seconds since your birth, then calls `localtime()` on that difference. The resulting `struct tm` is checked against three conditions involving day, month, and year fields. Two of those conditions are trivially satisfied by any valid date. The third is a signed-byte overflow trick: the year field difference is compared using only its least significant byte as a **signed** comparison — causing an integer wraparound that flips the outcome when the year difference has `0x7F` in its LSB, i.e. when the difference is `127 + k×256` years for any non-negative integer `k`.

|                       | Detail                                                            |
| --------------------- | ----------------------------------------------------------------- |
| **Input format**      | `MM/DD/YYYY` via `scanf("%20s")` → `strptime(s, "%m/%d/%Y", &tm)` |
| **Core logic**        | Computes `localtime(time(NULL) - mktime(birth_date))`             |
| **Anti-debug**        | Sends `SIGSTOP` to itself — discovered when GDB halts on launch   |
| **Key bug**           | Year comparison uses only the LSB (`cl` vs `dl`) with signed `jg` |
| **Winning condition** | Day ∈ {30,31} AND month == 11 AND (year\_diff % 256) == 127       |
| **Strategy**          | Subtract 128 years (or 384, 640, …) minus 1 day from today        |

***

### Tooling

| Tool                              | Purpose                                                              |
| --------------------------------- | -------------------------------------------------------------------- |
| `file`, `strings`                 | Initial binary triage                                                |
| `gdb`                             | Locating the entry point, observing anti-debug behaviour             |
| `IDA Pro` / `objdump -d -M intel` | Static disassembly — reading main, the checks, and the win condition |
| `python3`                         | Keygen (`keygen.py`) — generates valid date inputs for today's date  |

***

### 1. Initial Triage

```console
$ file date_of_birth
date_of_birth: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
               dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped

$ strings date_of_birth | grep -E 'Welcome|birth|date|done|correct|wrong'
Welcome to Discard App -- a new way to discard your personal information!
%20s
%m/%d/%Y
```

Key observations:

* **Dynamically linked** — libc functions (`scanf`, `strptime`, `mktime`, `time`, `localtime`, `puts`) are visible in the PLT, which immediately tells us the binary is doing date arithmetic rather than custom crypto.
* **Stripped** — no symbol names, but since the binary is small and leans on well-known libc functions, this barely slows us down.
* **`%m/%d/%Y`** — the date format string is a dead giveaway: the binary is parsing a date in `month/day/year` format.
* **`%20s`** — the input is capped at 20 characters, just enough for a full `MM/DD/YYYY` date.

***

### 2. Behavioural Analysis

```console
$ ./date_of_birth
Welcome to Discard App -- a new way to discard your personal information!
We need to verify your identity.
Please type your date of birth: 01/01/2000
Sorry, you are not who you say you are.

$ ./date_of_birth
Welcome to Discard App -- a new way to discard your personal information!
We need to verify your identity.
Please type your date of birth: 6/29/1898
Congratulations! You are who you say you are!
```

Wrong date → failure message. Correct date → congratulations. The check is entirely date-dependent — there is no password, no flag text to find.

***

### 3. Anti-Debug — SIGSTOP

Before reaching the disassembly, the first thing I tried was GDB:

```console
$ gdb ./date_of_birth
(gdb) info file
Entry point: 0x8c0
(gdb) b *0x8c0
Breakpoint 1 at 0x8c0
(gdb) r
Starting program: .../date_of_birth

[2]+  Stopped     gdb date_of_birth
```

GDB itself got `SIGSTOP` and was paused by the shell. Resuming with `fg`:

```console
$ fg
gdb date_of_birth
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x8c0
```

The binary sends `SIGSTOP` to itself early in execution (likely via `raise(SIGSTOP)` or `kill(getpid(), SIGSTOP)`), which halts the entire process group — including GDB. By the time GDB is resumed, the binary has already relocated and the original entry address is no longer mapped. **The debugger is effectively neutralised.**

The fix is to work statically: load the binary in IDA or run `objdump` and read the logic without ever attaching a debugger.

***

### 4. Finding main via Entry Point

Even without symbols, `gdb info file` revealed the entry point: `0x8c0`. Following the standard `_start` → `__libc_start_main` → `main` call chain in the disassembly, `main` is located at `0x710`.

The first few instructions of `main` confirm it:

```asm
.text:0000557E6212F710   push  r13
.text:0000557E6212F712   push  r12
.text:0000557E6212F714   mov   r13d, edi          ; save argc
.text:0000557E6212F717   push  rbp
.text:0000557E6212F718   push  rbx
.text:0000557E6212F719   lea   rdi, s             ; "Welcome to Discard App..."
.text:0000557E6212F720   sub   rsp, 98h           ; allocate 0x98 bytes of stack
.text:0000557E6212F727   mov   rax, fs:28h        ; stack canary
.text:0000557E6212F730   mov   [rsp+0B8h+var_30], rax
.text:0000557E6212F738   xor   eax, eax
.text:0000557E6212F73A   call  _puts              ; print welcome message
```

The stack canary at `fs:28h` means the binary has stack protection enabled — it cannot be solved via a buffer overflow. The stack frame is about 0x98 bytes, large enough to hold a `struct tm` and a 21-byte string buffer.

***

### 5. The Input — scanf with Date Format

```asm
; ── zero the input buffer and tm struct ──────────────────────────────────────
.text:0000557E6212F761   pxor    xmm0, xmm0
.text:0000557E6212F765   lea     rdi, format       ; "%20s"
.text:0000557E6212F76C   mov     rsi, rbp          ; dest: char s[21] on stack
.text:0000557E6212F76F   xor     eax, eax
.text:0000557E6212F771   mov     [rsp+0B8h+var_38], 0
.text:0000557E6212F77C   movaps  xmmword ptr [rsp+0B8h+s], xmm0
.text:0000557E6212F781   movaps  [rsp+0B8h+var_B8], xmm0
.text:0000557E6212F785   call    _scanf            ; scanf("%20s", s)
```

Before calling `scanf`, the binary zeroes two 16-byte regions with `xmm0` and sets one more dword to zero. This pre-nulls both the input buffer `s` and the `struct tm` that will be written by `strptime`, ensuring valid null-terminated strings regardless of input length (up to the 20-character limit).

***

### 6. Parsing the Date — strptime and mktime

```asm
; ── strptime(s, "%m/%d/%Y", &birth_date) ─────────────────────────────────────
.text:0000557E6212F78A   lea   rsi, fmt           ; "%m/%d/%Y"   (format)
.text:0000557E6212F791   mov   rdx, rbx           ; &birth_date  (struct tm*)
.text:0000557E6212F794   mov   rdi, rbp           ; s            (input string)
.text:0000557E6212F797   movdqa xmm0, [rsp+0B8h+var_B8]
.text:0000557E6212F79C   mov   [rsp+0B8h+tp.tm_zone], 0
.text:0000557E6212F7A5   movaps xmmword ptr [rsp+0B8h+tp.tm_sec], xmm0
.text:0000557E6212F7AA   movaps xmmword ptr [rsp+0B8h+tp.tm_mon], xmm0
.text:0000557E6212F7AF   movaps xmmword ptr [rsp+0B8h+tp.tm_isdst], xmm0
.text:0000557E6212F7B4   call  _strptime

; ── mktime(&birth_date) → seconds since epoch ────────────────────────────────
.text:0000557E6212F7B9   mov   rdi, rbx           ; &birth_date
.text:0000557E6212F7BC   call  _mktime            ; returns time_t in rax
```

`strptime` fills in `tm_mon`, `tm_mday`, and `tm_year` from the input string. `mktime` converts the `struct tm` into a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC). The timestamp is returned in `RAX`.

In C pseudocode:

```c
char s[21];
struct tm birth_date = {0};
scanf("%20s", s);
strptime(s, "%m/%d/%Y", &birth_date);
time_t birth_seconds = mktime(&birth_date);
```

***

### 7. Computing the Difference — time() and localtime()

```asm
; ── get current time ──────────────────────────────────────────────────────────
.text:0000557E6212F7C1   xor   edi, edi           ; time(NULL)
.text:0000557E6212F7C3   mov   rbx, rax           ; rbx = birth_seconds (save)
.text:0000557E6212F7C6   call  _time              ; rax = current time (seconds)

; ── first localtime call — effectively unused ─────────────────────────────────
.text:0000557E6212F7CB   lea   rdi, [rsp+0B8h+timer]
.text:0000557E6212F7D0   mov   [rsp+0B8h+timer], rax
.text:0000557E6212F7D5   call  _localtime         ; result immediately overwritten

; ── compute difference, call localtime on it ─────────────────────────────────
.text:0000557E6212F7DA   mov   rax, [rsp+0B8h+timer]  ; rax = current_seconds
.text:0000557E6212F7DF   lea   rdi, [rsp+0B8h+var_90]
.text:0000557E6212F7E4   sub   rax, rbx               ; rax = current - birth
.text:0000557E6212F7E7   mov   [rsp+0B8h+var_90], rax ; store diff
.text:0000557E6212F7EC   call  _localtime              ; localtime(&diff) → struct tm* in rax
```

The first `localtime` call is a red herring — its return value is immediately overwritten by the next `mov`. The important call is the second one: `localtime(current_seconds - birth_seconds)`.

`localtime` treats the difference as a Unix timestamp and converts it to a `struct tm`. So if you were born 128 years ago, the "timestamp" is ≈ 128 years of seconds, and `localtime` gives back a date/time that is 128 years after the Unix epoch (1970).

```c
time_t now  = time(NULL);
time_t diff = now - birth_seconds;
struct tm* t = localtime(&diff);   // t represents: epoch + diff seconds
```

***

### 8. The Three-Branch Check

The returned `struct tm*` is in `RAX`. The binary reads three fields:

```asm
.text:0000557E6212F7F1   mov  r12d, [rax+0Ch]    ; r12d = tm_mday  (day of month, 1-31)
.text:0000557E6212F7F5   mov  ebx,  [rax+14h]    ; ebx  = tm_year  (years since 1900)
.text:0000557E6212F7F8   mov  ebp,  [rax+10h]    ; ebp  = tm_mon   (month, 0-11)
```

The `struct tm` field offsets (all `int`, so 4 bytes each):

| Field     | Offset | Meaning             |
| --------- | ------ | ------------------- |
| `tm_sec`  | `0x00` | Seconds (0–60)      |
| `tm_min`  | `0x04` | Minutes (0–59)      |
| `tm_hour` | `0x08` | Hours (0–23)        |
| `tm_mday` | `0x0C` | Day of month (1–31) |
| `tm_mon`  | `0x10` | Month (0–11, Jan=0) |
| `tm_year` | `0x14` | Year − 1900         |

The binary then subtracts 70 (0x46) from `tm_year` to get years since the Unix epoch:

```asm
.text:0000557E6212F800   sub  ebx, 46h            ; ebx = tm_year - 70 = actual_year - 1970
.text:0000557E6212F803   mov  edx, ebx            ; edx = year_diff (save copy)
```

Now the three checks:

#### Check 1 — Day must be 30 or 31

```asm
.text:0000557E6212F7FB   lea  eax, [r12+1]        ; eax = tm_mday + 1
.text:0000557E6212F805   cmp  al, 1Eh             ; (tm_mday + 1) <= 30?
.text:0000557E6212F807   jle  loc_F853            ; yes (day <= 29) → branch A (dead end)
                                                  ; no  (day >= 30) → branch B (continue)
```

If `tm_mday <= 29`: branch A → leads eventually to the failure message via a dead-end path. If `tm_mday >= 30`: branch B → continue to Check 2.

#### Check 2 — Month must be 11 (December, zero-indexed)

```asm
; ── reached only if day >= 30 ────────────────────────────────────────────────
.text:0000557E6212F809   lea  ecx, [rbp+1]        ; ecx = tm_mon + 1  (1-indexed month)
.text:0000557E6212F80E   cmp  cl, 0Bh             ; (tm_mon + 1) > 11?
.text:0000557E6212F811   jg   loc_F859            ; yes (month == 11) → Check 3
                                                  ; no  (month <= 10) → dead end
```

`tm_mon` ranges 0–11. If `tm_mon == 11` (December in `struct tm`), then `tm_mon + 1 = 12 > 11` and we proceed to Check 3. Any other month falls through to `cmp bpl, cl` (`month >= month+1`), which is always false — instant failure.

#### Check 3 — The Overflow Trick

```asm
; ── reached only if day >= 30 AND month == 11 ────────────────────────────────
.text:0000557E6212F859   lea  ecx, [rbx+1]        ; ecx = year_diff + 1
.text:0000557E6212F85C   cmp  cl, dl              ; (year_diff + 1) > year_diff ?  — AS SIGNED BYTES
.text:0000557E6212F85E   jg   loc_F81C            ; yes → dead end (failure)
                                                  ; no  → VICTORY
```

This is the key. The comparison only uses `cl` and `dl` — the **least significant bytes** of `ecx` and `edx`. And `jg` is a **signed** comparison.

* `dl` = LSB of `year_diff`
* `cl` = LSB of `year_diff + 1`

Normally, `year_diff + 1 > year_diff` is always true and we'd always fail. But if `year_diff & 0xFF == 0x7F` (127):

* `dl = 0x7F` = **+127** (signed)
* `cl = 0x80` = **−128** (signed, because bit 7 is set)
* `cl > dl` → `−128 > 127` → **FALSE** → `jg` does NOT jump → we fall through to victory

***

### 9. The Winning Condition — Signed Byte Overflow

Putting all three conditions together, we need `localtime(now - birth_seconds)` to return a `struct tm` where:

| Field                   | Required value | Meaning                                     |
| ----------------------- | -------------- | ------------------------------------------- |
| `tm_mday`               | 30 or 31       | Difference lands on 30th or 31st of a month |
| `tm_mon`                | 11             | That month is "December" in epoch time      |
| `(tm_year - 70) & 0xFF` | `0x7F` (127)   | LSB of year difference is 127               |

The third condition means `localtime(diff)` represents a year of `1970 + 127 + k×256` for any non-negative integer `k`:

```
year ∈ { 2097, 2353, 2609, ... }
```

So the difference between now and the birth date, when interpreted as a Unix timestamp, must land on **December 30 or 31 of year 2097, 2353, 2609, …**

Since `2097 - 1970 = 127` years, a valid birth date is approximately **127 years, 11 months, and 30/31 days before today**.

The cleanest way to construct this: birth date = `(today + 1 day)` in year `(current_year - 128)`. That gives a difference of exactly 128 years − 1 day, which `localtime` interprets as December 31 of year `1970 + 127 = 2097`:

```
diff = 128 years − 1 day
localtime(diff) = Dec 31, 2097
  tm_mday = 31  ✓ (≥ 30)
  tm_mon  = 11  ✓ (December)
  year − 1970 = 127 = 0x7F  ✓ (LSB overflow)
```

Adding 256-year multiples still works: `128 + 256k` years − 1 day for k = 0, 1, 2, …

***

### 10. The Keygen — Computing Valid Dates

**`keygen.py`:**

```python
from datetime import date, timedelta
import random

keys = []

i = 0
today = date.today()
while True:
    year_diff = 128 + i * 256           # 128, 384, 640, ... years of difference
    if year_diff >= today.year:         # can't go before year 1
        break
    # birth_date = (today + 1 day) but year_diff years earlier
    birth = date(year=today.year - year_diff, month=today.month, day=today.day) \
            + timedelta(days=1)
    keys.append(birth)
    i += 1

key = keys[random.randint(0, len(keys) - 1)]
print("{}/{}/{}".format(key.month, key.day, key.year))
```

**Why `today + 1 day` instead of `today`?**

If the birth date were exactly today-minus-128-years, the difference would be `128 × 365.25 × 86400` seconds. `localtime` of that is approximately January 1, 2098 — the day count rolls into January, breaking `tm_mon == 11`. Shifting the birth date one day forward (making the difference one day shorter = 128 years − 1 day) lands us on **December 31, 2097** instead.

**Sample output for June 28, 2026:**

```
6/29/1898    (diff = 127 years, 11 months, 30 days → Dec 30/31 2097)
6/29/1642    (diff = 383 years, 11 months, 30 days → Dec 30/31 2353)
6/29/1386
6/29/1130
6/29/874
6/29/618
6/29/362
6/29/106
```

***

### 11. Full Solver (PoC)

```console
$ python3 keygen.py
6/29/1898

$ echo "6/29/1898" | ./date_of_birth
Welcome to Discard App -- a new way to discard your personal information!
We need to verify your identity.
Please type your date of birth:
Congratulations! You are who you say you are!
```

***

### 12. Reproduction Steps

#### Prerequisites

```bash
# Linux x86-64 or WSL2 on Windows
python3 --version      # any Python 3.x
sudo apt-get install -y binutils    # for objdump (optional, IDA works too)
```

#### Step 1 — Get the binary

Download from [crackmes.one](https://crackmes.one/crackme/5f855fe333c5d424269a14ed). Extract with the standard password `crackmes.one`.

```bash
chmod +x date_of_birth
```

#### Step 2 — Confirm baseline behaviour

```console
$ echo "01/01/2000" | ./date_of_birth
Sorry, you are not who you say you are.
```

#### Step 3 — Confirm the anti-debug

```bash
$ gdb ./date_of_birth
(gdb) info file
# note the entry point, e.g. 0x8c0
(gdb) b *0x8c0
(gdb) r
# GDB will be SIGSTOP'd — type fg to resume, then observe breakpoint failure
```

Since GDB is neutralised, switch to static analysis in IDA or objdump.

#### Step 4 — Generate a valid date

```console
$ python3 keygen.py
6/29/1898
```

#### Step 5 — Verify against the binary

```console
$ echo "6/29/1898" | ./date_of_birth
Congratulations! You are who you say you are!
```

***

### 13. Confirming on the Binary

To confirm the overflow without a debugger, manually verify the expected `struct tm` values by computing them independently:

```python
from datetime import datetime, timezone
import time, calendar

birth  = datetime(1898, 6, 29, tzinfo=timezone.utc)
now    = datetime.now(timezone.utc)
diff_s = int((now - birth).total_seconds())

# Replicate what localtime() returns
import time as t
lt = t.gmtime(diff_s)     # gmtime ≈ localtime for our purposes
print(f"tm_mday : {lt.tm_mday}")   # expect 30 or 31
print(f"tm_mon  : {lt.tm_mon - 1}")  # expect 11 (tm_mon is 1-indexed in Python)
print(f"tm_year : {lt.tm_year}")   # expect year with (year-1970) & 0xFF == 0x7F
print(f"(year-1970) & 0xFF = {(lt.tm_year - 1970) & 0xFF:#x}")  # expect 0x7f
```

```
tm_mday : 30
tm_mon  : 11
tm_year : 2097
(year-1970) & 0xFF = 0x7f     ← triggers the signed-byte overflow → victory
```

All three conditions satisfied. The `jg cl, dl` comparison (`-128 > 127` signed) evaluates to false, bypassing the failure branch and landing at the congratulations message.

***

### Appendix: Key Addresses & Structures

#### Key Addresses

| Address (relative) | Meaning                                                      |
| ------------------ | ------------------------------------------------------------ |
| `0x710`            | `main` entry                                                 |
| `0x719`            | `lea rdi, s` — load welcome string                           |
| `0x727`            | `mov rax, fs:28h` — stack canary setup                       |
| `0x73A`            | `call _puts` — print welcome message                         |
| `0x765`            | `lea rdi, format` — load `"%20s"`                            |
| `0x785`            | `call _scanf` — read user date string                        |
| `0x78A`            | `lea rsi, fmt` — load `"%m/%d/%Y"`                           |
| `0x7B4`            | `call _strptime` — parse date string into `struct tm`        |
| `0x7BC`            | `call _mktime` — convert `struct tm` to Unix timestamp       |
| `0x7C1`            | `xor edi, edi` — prepare `time(NULL)`                        |
| `0x7C6`            | `call _time` — get current Unix timestamp                    |
| `0x7D5`            | `call _localtime` — first call (result discarded)            |
| `0x7E4`            | `sub rax, rbx` — compute `now - birth_seconds`               |
| `0x7EC`            | `call _localtime` — second call: convert diff to `struct tm` |
| `0x7F1`            | `mov r12d, [rax+0Ch]` — load `tm_mday`                       |
| `0x7F5`            | `mov ebx, [rax+14h]` — load `tm_year`                        |
| `0x7F8`            | `mov ebp, [rax+10h]` — load `tm_mon`                         |
| `0x800`            | `sub ebx, 46h` — compute `tm_year - 70` (years since epoch)  |
| `0x805`            | `cmp al, 1Eh` — Check 1: `tm_mday + 1 <= 30`?                |
| `0x80E`            | `cmp cl, 0Bh` — Check 2: `tm_mon + 1 > 11`?                  |
| `0x85C`            | `cmp cl, dl` — **Check 3: LSB signed byte comparison**       |
| `0x85E`            | `jg loc_F81C` — if `cl > dl` (signed) → fail; else → WIN     |

#### struct tm Layout (from `<time.h>`)

```c
struct tm {
    int tm_sec;    // offset 0x00 — Seconds     (0–60)
    int tm_min;    // offset 0x04 — Minutes     (0–59)
    int tm_hour;   // offset 0x08 — Hours       (0–23)
    int tm_mday;   // offset 0x0C — Day         (1–31)   ← read at [rax+0Ch]
    int tm_mon;    // offset 0x10 — Month       (0–11)   ← read at [rax+10h]
    int tm_year;   // offset 0x14 — Year − 1900          ← read at [rax+14h]
    int tm_wday;   // offset 0x18 — Weekday     (0–6)
    int tm_yday;   // offset 0x1C — Day of year (0–365)
    int tm_isdst;  // offset 0x20 — DST flag
};
```

#### The Overflow in Detail

```
year_diff = (tm_year - 1900) - 70 = tm_year - 1970

For year_diff = 127 (0x7F):
  dl = year_diff & 0xFF  = 0x7F = +127  (signed byte)
  cl = (year_diff+1) & 0xFF = 0x80 = -128  (signed byte — overflows!)
  jg: is cl(-128) > dl(127)?  → NO → skip failure → WIN ✓

For year_diff = 383 (0x17F, next valid case):
  dl = 0x7F = +127
  cl = 0x80 = -128
  Same overflow → WIN ✓  (256-year periodicity)

For any other year_diff:
  cl = dl + 1 > dl  → YES → jg jumps to failure → LOSE ✗
```

#### Valid Year Differences

```
year_diff = 127 + k×256  for k = 0, 1, 2, ...
          = 127, 383, 639, 895, 1151, 1407, 1663, 1919, ...

Corresponding birth years (from June 28, 2026):
  2026 - (127+1) = 1898   → "6/29/1898"
  2026 - (383+1) = 1642   → "6/29/1642"
  2026 - (639+1) = 1386   → "6/29/1386"
  ... and so on
```

***

_Solved with IDA static analysis (anti-debug prevented GDB), identifying the `strptime`/`mktime`/`localtime` date pipeline, tracing the three conditional branches, and spotting the signed byte overflow in the year comparison at `0x85C`. The keygen generates all valid inputs for any given current date._
