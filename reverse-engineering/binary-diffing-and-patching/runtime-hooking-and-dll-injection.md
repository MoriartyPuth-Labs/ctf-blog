# Runtime Hooking & DLL Injection

Intercepting dynamic function calls using `LD_PRELOAD` on Linux and Windows DLL Injection / IAT Hooking.

***

### 1. Linux `LD_PRELOAD` Function Interception

Override glibc functions without altering binary bytes:

```c
// Save as hook.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int strcmp(const char *s1, const char *s2) {
    printf("[+] Hooked strcmp!\n  s1: %s\n  s2: %s\n", s1, s2);
    int (*real_strcmp)(const char*, const char*) = dlsym(RTLD_NEXT, "strcmp");
    return real_strcmp(s1, s2);
}
```

Build: `gcc -shared -fPIC hook.c -o hook.so -ldl`\
Run: `LD_PRELOAD=./hook.so ./binary`

***

### 2. Windows Import Address Table (IAT) Hooking

IAT hooking modifies target API pointers inside the process Import Address Table:

```c
// Overwrite VirtualProtect pointer in IAT with address of HookedVirtualProtect
PIMAGE_THUNK_DATA pThunk = FindIatThunk(hModule, "VirtualProtect");
DWORD dwOld;
VirtualProtect(&pThunk->u1.Function, sizeof(LPVOID), PAGE_READWRITE, &dwOld);
pThunk->u1.Function = (ULONG_PTR)&HookedVirtualProtect;
VirtualProtect(&pThunk->u1.Function, sizeof(LPVOID), dwOld, &dwOld);
```
