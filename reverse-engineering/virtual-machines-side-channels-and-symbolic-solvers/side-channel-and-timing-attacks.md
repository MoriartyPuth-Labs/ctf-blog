# Side-Channel & Timing Attacks

Using instruction counting, `LD_PRELOAD` time hooks, and cache timing side-channels to brute-force flag bytes character-by-character without full reversing.

***

### 1. Instruction Counting Side-Channel

When a binary compares a user input string character-by-character:

```c
for (int i = 0; i < len; i++) {
    if (user_input[i] != flag[i]) {
        return 0; // Exits loop early on first wrong byte!
    }
}
```

#### Key Insight

Each correct input character executes **more CPU instructions** before failing. By measuring executed instruction counts, you can brute-force the flag byte-by-byte!

***

### 2. Instruction Counting using `valgrind` / `callgrind`

```bash
# 1. Run binary under valgrind callgrind
valgrind --tool=callgrind --callgrind-out-file=out.log ./binary "FLAG{A...}"

# 2. Extract total instruction count
grep "summary:" out.log | awk '{print $2}'
```

#### Python Automated Character-by-Character Brute Force Script

```python
import subprocess, string

alphabet = string.ascii_letters + string.digits + "{}_!"
flag = ""

for pos in range(32):
    max_instr = 0
    best_char = ""
    
    for c in alphabet:
        test_input = flag + c + "A" * (31 - pos)
        cmd = f"valgrind --tool=callgrind --callgrind-out-file=tmp.log ./binary '{test_input}' 2>&1"
        subprocess.run(cmd, shell=True, capture_output=True)
        
        # Read instruction count
        with open("tmp.log") as f:
            for line in f:
                if "summary:" in line:
                    count = int(line.split()[1])
                    if count > max_instr:
                        max_instr = count
                        best_char = c
                        
    flag += best_char
    print(f"[+] Current Leaked Flag: {flag}")
```

***

### 3. `LD_PRELOAD` `memcmp` / `strcmp` Hooking Oracle

Force shared library function hooks to print comparison arguments dynamically at runtime:

```c
// Save as hook_cmp.c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

int memcmp(const void *s1, const void *s2, size_t n) {
    printf("[+] Hooked memcmp!\n  s1: %s\n  s2: %s\n", (char*)s1, (char*)s2);
    int (*real_memcmp)(const void *, const void *, size_t) = dlsym(RTLD_NEXT, "memcmp");
    return real_memcmp(s1, s2, n);
}
```

Build & run:

```bash
gcc -shared -fPIC hook_cmp.c -o hook_cmp.so -ldl
LD_PRELOAD=./hook_cmp.so ./binary
```
