# Android & Mobile Application RE

Reverse engineering Android APKs, DEX bytecode, JNI native shared libraries (`.so`), and Frida dynamic instrumentation hooks.

***

### 1. Static APK Extraction & Decompilation

```bash
# 1. Unpack APK Resources & AndroidManifest.xml
apktool d app.apk -o apk_out

# 2. Decompile DEX to Readable Java via JADX
jadx -d ./jadx_out app.apk
# Or launch JADX GUI directly:
jadx-gui app.apk
```

***

### 2. Reversing Native JNI Libraries (`libnative.so`)

Android apps often execute critical flag checks or crypto inside compiled C/C++ shared libraries loaded via JNI (`System.loadLibrary("native-lib")`).

#### Locating JNI Native Methods

1. Unzip APK: `unzip app.apk -d app_unzipped`
2. Locate native libraries: `app_unzipped/lib/arm64-v8a/libnative-lib.so`
3. Load `libnative-lib.so` into Ghidra / IDA.
4. Search for `Java_package_name_ClassName_methodName` or inspect `JNI_OnLoad` for dynamic registration via `RegisterNatives()`.

***

### 3. Frida Android Dynamic Hooking

Use Frida to hook Java methods and native C functions dynamically without recompiling the APK.

#### Frida Hooking Template (`hook.js`)

```javascript
Java.perform(function () {
    // 1. Hook Java Target Method
    let MainActivity = Java.use("com.example.app.MainActivity");
    
    MainActivity.checkFlag.implementation = function (userInput) {
        console.log("[+] Intercepted checkFlag input: " + userInput);
        
        // Execute original method and capture return value
        let result = this.checkFlag(userInput);
        console.log("[+] Original Return Value: " + result);
        
        return true; // Force return true (Bypass check!)
    };
});
```

#### Executing Frida Script on Device / Emulator

```bash
# Connect to running app via USB Frida server
frida -U -f com.example.app -l hook.js
```
