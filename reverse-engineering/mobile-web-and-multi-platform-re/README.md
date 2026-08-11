# Mobile, Web & Multi-Platform RE

### Android Mobile Application RE

Android applications combine Java/Kotlin bytecode (`.dex`) with native C/C++ shared libraries (`.so`).

#### Android RE Pipeline

1. **Unpack & Decompile APK:** Use `apktool d app.apk` to extract resources, and `jadx app.apk` to decompile DEX to Java source code.
2. **Reversing Native Libraries (JNI):** Locate `lib/arm64-v8a/libnative.so`. Trace `Java_package_class_method` exports or inspect `JNI_OnLoad` for dynamic method registration (`RegisterNatives`).
3. **Frida Dynamic Hooking:** Intercept Java methods or native C functions at runtime to alter return values (`return true`).

***

### WebAssembly (WASM) Module RE

WebAssembly (`.wasm`) is a stack-based bytecode format executed inside browser environments.

#### WASM Analysis Workflow

1. **Convert to Text Format (`.wat`):** Run `wasm2wat target.wasm -o target.wat`.
2. **Decompile to C Pseudocode:** Run `wasm-decompile target.wasm -o target.c`.
3. **Browser DevTools Debugging:** Inspect WASM memory (`HEAP32`) and set breakpoints on stack instructions (`i32.eq`, `i32.xor`).

***

### macOS & iOS Mach-O Reversing

Mach-O (Mach Object) binaries run on macOS and iOS devices.

#### Key Concepts

* **Universal / Fat Binaries:** Contain multiple architecture slices (x86\_64, arm64). Extract using `lipo -thin arm64 target -output thin_binary`.
* **Objective-C `objc_msgSend` Messaging:** Objective-C calls translate to `objc_msgSend(receiver, selector, args...)`. Search for selector strings in `.objc_selrefs` to trace event handlers.
