# Hardware, Firmware, & Kernel Drivers

## RE Cheatsheet: Hardware, Firmware, & Kernel Drivers

Reversing IoT firmware images, Linux kernel modules (`.ko`), eBPF bytecode, Windows kernel drivers (`.sys`), and hardware embedded architectures (ARM/MIPS/RISC-V).

***

### 1. Firmware Unpacking (`binwalk`)

```bash
# 1. Inspect Firmware Image Layout
binwalk firmware.bin

# 2. Extract Embedded Filesystems (SquashFS, CramFS, JFFS2)
binwalk -e -M firmware.bin
```

***

### 2. Linux Kernel Modules (`.ko`) & eBPF Reversing

#### 2.1 Reversing `.ko` Kernel Drivers

1. Inspect kernel symbol exports: `readelf -s module.ko`
2. Load `module.ko` into Ghidra / IDA.
3. Locate `init_module()` or `module_init()` entry point.
4. Inspect `ioctl` handler table (`unlocked_ioctl`) for custom command dispatching logic.

#### 2.2 eBPF Bytecode Reversing

Extract and disassemble eBPF socket/kprobe filters using `bpftool` or `llvm-objdump`:

```bash
llvm-objdump -d -m bpf ebpf_program.o
```

***

### 3. Windows Kernel Drivers (`.sys`)

#### Key Components

* **`DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)`:** Driver initialization entry point.
* **`IRP_MJ_DEVICE_CONTROL` Handler:** Major function handler for user-mode `DeviceIoControl()` calls.

#### Reversing `DeviceIoControl` Handler

1. Locate `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControlHandler`.
2.  Reverse `IoControlHandler`: Extract `IoControlCode` (IOCTL code) switch cases:

    ```c
    switch (IoControlCode) {
        case 0x222004: // Custom IOCTL handling function
            process_user_buffer(Irp->AssociatedIrp.SystemBuffer);
            break;
    }
    ```
