# macOS & iOS Mach-O Reversing

Reversing Apple Mach-O binaries, Objective-C runtime messaging (`objc_msgSend`), Swift protocol witness tables, dyld shared cache extraction, and Frida iOS dynamic hooks.

***

### 1. Mach-O Binary Architecture & Tools

Mach-O (Mach Object) is the binary executable format for macOS and iOS.

```bash
# Inspect Mach-O Headers & Architectures (Fat/Universal Binaries)
lipo -info target_app          # List supported architectures (x86_64, arm64)
lipo target_app -thin arm64 -output app_arm64 # Extract thin 64-bit ARM binary

otool -l app_arm64             # Inspect Load Commands (LC_LOAD_DYLIB, LC_MAIN)
otool -L app_arm64             # List linked shared dylib libraries
```

***

### 2. Objective-C Runtime & `objc_msgSend`

Objective-C methods are invoked dynamically via messaging dispatchers:

```objc
[target_object myMethod:arg1 withArg:arg2];
// Translates in C to:
objc_msgSend(target_object, sel_registerName("myMethod:withArg:"), arg1, arg2);
```

#### Reversing `objc_msgSend` in Ghidra / IDA

1. Argument 1 (`RDI` / `X0`): Pointer to receiver object.
2. Argument 2 (`RSI` / `X1`): **Selector string (`SEL`)** name (e.g. `"validateSerial:key:"`).
3. Remaining Arguments (`RDX`, `RCX` / `X2`, `X3`): Method parameters.

> **Tip:** Search for selector strings in `.objc_selrefs` data section to instantly trace button handlers and validation callbacks!

***

### 3. Swift Binary Reversing & Demangling

Swift uses mangled symbols starting with `$s` or `_$s`.

```bash
# Demangle Swift Symbol Names
swift demangle "_$s4main12validateFlagys6BoolVSS1s_tF"
# Output: main.validateFlag(s: Swift.String) -> Swift.Bool
```

#### Swift Memory Patterns

* **Swift String:** Passed as a 16-byte pair: `[ Length / Flags (8B) ] + [ Buffer Pointer (8B) ]`.
* **`Option<T>` & `Result<T, E>`:** Use discriminant enum tags stored at offset + payload size.

***

### 4. Frida iOS Dynamic Hooking

```javascript
// Frida iOS Script: Hook Objective-C Method
if (ObjC.available) {
    let className = "FlagValidator";
    let funcName = "- checkLicenseKey:";
    
    let hook = ObjC.classes[className][funcName];
    Interceptor.attach(hook.implementation, {
        onEnter: function (args) {
            let key = new ObjC.Object(args[2]); // Arg 2 is 1st method parameter
            console.log("[+] Intercepted License Key: " + key.toString());
        },
        onLeave: function (retval) {
            retval.replace(ptr("0x1")); // Force return TRUE!
        }
    });
}
```
