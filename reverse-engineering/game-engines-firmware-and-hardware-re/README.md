# Game Engines, Firmware & Hardware RE

### Unity & Unreal Game Engine Reversing

#### Unity Mono vs. IL2CPP

* **Unity Mono:** Logic is stored in C# DLLs (`Assembly-CSharp.dll`). Open directly in **dnSpy** or **ILSpy** for full source code!
* **Unity IL2CPP:** Compiles C# logic into native binaries (`GameAssembly.dll` / `libil2cpp.so`).
  * _Recovery:_ Run **Il2CppDumper** on `GameAssembly.dll` and `global-metadata.dat` to generate Ghidra/IDA scripts that restore C# classes, methods, and field offsets.

#### Asset Extraction

* **Godot (`.pck`):** Extract GDScript assets using `gdre_tools`.
* **Unreal Engine (`.pak`):** Extract UE pak assets using `unreal_unpacker`.

***

### IoT Firmware & Embedded Hardware RE

1. **Firmware Extraction (`binwalk`):** Scan firmware images with `binwalk -e -M firmware.bin` to unpack embedded filesystems (SquashFS, CramFS, JFFS2).
2. **Architecture Analysis:** Reverse MIPS, ARM, or RISC-V ELF binaries extracted from rootfs.
3. **Hardware Interfaces:** Reversing GPIO pins, serial UART consoles, JTAG debugging headers, and SPI flash memory dumps.

***

### Kernel Driver Reversing (Linux `.ko` & Windows `.sys`)

* **Linux Kernel Modules (`.ko`):** Inspect `module_init` and `unlocked_ioctl` handlers for custom kernel command processing.
* **Windows Kernel Drivers (`.sys`):** Locate `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]` to reverse `DeviceIoControl()` IOCTL code switch cases.
