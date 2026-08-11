# Dynamic Analysis with GDB, pwndbg, & Tracing

Dynamic tracing, GDB debugging, PIE address resolution, memory dumping, and ltrace/strace side-channel tricks.

***

### 1. System Call & Library Tracing (`strace` / `ltrace`)

```bash
# 1. Trace Library Function Calls (strcmp, memcmp, ptrace)
ltrace -s 200 -f ./binary

# 2. Trace Kernel System Calls (read, write, openat)
strace -s 500 -f ./binary

# 3. Capture ltrace output to file while providing input
echo "A" * 32 | ltrace -o ltrace.log ./binary
```

***

### 2. GDB & pwndbg Command Cheatsheet

```bash
gdb ./binary

# Initialization & Breakpoints
entry                      # Break at binary entry point
start                      # Start execution & break at main
b *main                    # Break at main function
b *main+0x42               # Break at offset from main
b *0x00401234              # Break at absolute instruction address

# Memory Inspection & Register Control
info registers             # Print all CPU registers
x/20i $rip                 # Inspect 20 instructions at RIP
x/32wx $rsp                # Inspect 32 hex words at RSP
x/s $rdi                   # Inspect string at RDI (e.g. strcmp argument)

# Control Flow Execution
c                          # Continue execution
si                         # Step Instruction (step into calls)
ni                         # Next Instruction (step over calls)
finish                     # Run until current function returns
```

***

### 3. Position Independent Executable (PIE) Relative Debugging

PIE binaries randomize base addresses on every run. Use relative breakpoints inside GDB:

```bash
# Method 1: Use pwndbg 'breakrva' (Break Relative Virtual Address)
pwndbg> breakrva 0x1234    # Breaks at PIE_BASE + 0x1234

# Method 2: Compute PIE Base manually
pwndbg> start
pwndbg> vmmap              # Print memory map to get PIE base address
pwndbg> b *(0x555555554000 + 0x1234)
```

***

### 4. Memory Dumping & Flag Extraction Strategy

Instead of reversing complex key schedule algorithms, let the binary compute the flag in memory, then dump it at the comparison point!

#### GDB Memory Dump Command Sequence

```bash
gdb ./binary
pwndbg> b *main+OFFSET     # Set breakpoint at final memcmp / strcmp
pwndbg> run                # Provide input of expected length
pwndbg> x/s $rsi           # Dump memory string argument 1 (computed flag!)
pwndbg> dump memory flag.bin $rsi $rsi+64 # Dump 64 raw bytes to file
```

***

### 5. Reverse Debugging with GDB & `rr`

Record and step backward through binary execution:

```bash
# 1. Record execution
rr record ./binary

# 2. Replay & Debug backward
rr replay
(rr) b *flag_checker
(rr) continue
(rr) reverse-stepi          # Step backward by 1 instruction!
(rr) reverse-continue       # Run backward to previous breakpoint
```
