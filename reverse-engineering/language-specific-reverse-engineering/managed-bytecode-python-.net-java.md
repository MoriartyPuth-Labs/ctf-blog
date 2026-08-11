# Managed Bytecode (Python, .NET, Java)

## RE Cheatsheet: Managed Bytecode (Python, .NET, Java)

Reversing Python bytecode (`.pyc`), .NET assemblies (`.exe`/`.dll`), and Java/JVM applications.

***

### 1. Python Bytecode Reversing (`.pyc` / PyArmor)

#### 1.1 Uncompyle6 / Decompyle++ (`pycdc`)

```bash
# Decompile Python .pyc byte-code back to readable .py source
uncompyle6 target.pyc > decompiled.py
pycdc target.pyc > decompiled.py
```

#### 1.2 Disassembling Raw Opcodes with Python `dis`

If decompilers fail due to custom opcode mapping:

```python
import dis, marshal

with open("target.pyc", "rb") as f:
    f.seek(16) # Skip 16-byte header (Python 3.8+)
    code_obj = marshal.load(f)
    dis.dis(code_obj)
```

***

### 2. .NET / C# Reversing (dnSpy / ILSpy)

.NET applications compile to Intermediate Language (IL) metadata, which decompiles almost perfectly to original C# source code.

#### Decompilation Tools

* **dnSpy / dnSpyEx:** Interactive debugger and decompiler for .NET assemblies. Allows dynamic debugging, setting breakpoints, and editing IL/C# code live in memory!
* **ILSpy:** Command-line and GUI .NET decompiler.

#### Unpacking .NET Obfuscators (ConfuserEx / Reactor)

Use automated unpackers: **de4dot**

```bash
de4dot target_obfuscated.exe -o target_cleaned.exe
```

***

### 3. Java & Android Bytecode (JADX / CFR)

#### Decompiling `.class` and `.jar` Files

```bash
# CFR Java Decompiler
java -jar cfr.jar target.class --outputdir ./src
```
