# Game Engines & Asset Extraction

## RE Cheatsheet: Game Engines & Asset Extraction

Reversing Unity (Mono / IL2CPP), Godot, Unreal Engine, Roblox place files, and asset unpackers.

***

### 1. Unity Game Reversing (Mono vs. IL2CPP)

#### 1.1 Unity Mono Binaries

Unity Mono games store logic in C# assembly DLLs located in `Game_Data/Managed/Assembly-CSharp.dll`.

* **Reversing Tool:** Load `Assembly-CSharp.dll` directly into **dnSpy** or **ILSpy** to view complete C# source code!

#### 1.2 Unity IL2CPP Binaries

Unity IL2CPP compiles C# code into native C++ binaries (`Game_Data/Native/GameAssembly.dll` or `libil2cpp.so`).

**IL2CPP Metadata Recovery (`Il2CppDumper`)**

1. Locate `GameAssembly.dll` (or `libil2cpp.so`) and `global-metadata.dat` (located in `Il2CppData/Metadata/`).
2.  Run **Il2CppDumper**:

    ```bash
    Il2CppDumper.exe GameAssembly.dll global-metadata.dat ./output
    ```
3. Load generated `script.py` / `ghidra_with_struct.py` into Ghidra/IDA to restore all C# class names, methods, and field offsets!

***

### 2. Godot & Unreal Engine Asset Extraction

#### 2.1 Godot Engine (`.pck` Files)

Extract compiled GDScript and assets using **gdsdecomp** (Godot RE tools):

```bash
gdre_tools --unpack target.pck
```

#### 2.2 Unreal Engine (`.pak` Files)

Extract UE assets using **unreal\_pak\_tool** or **unreal\_unpacker**:

```bash
unreal_unpacker game.pak ./extracted_assets
```
