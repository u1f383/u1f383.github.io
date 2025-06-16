---
layout: post
title:  "How to Run Native Binary on Android"
categories: android
---

## Overview

Android uses SELinux for permission control. Depending on how a program is loaded, it may run under different contexts. Typically, untrusted apps run under the `untrusted_app` context, while programs executed through `adb shell` run under the `shell` context.

The context determines what resources a program can access — for example, which files it can open or which system calls it can make. The specific restrictions depend on the SELinux policy. The complete policy can be found in the file `/sys/fs/selinux/policy`, but this file is not accessible to regular users. To analyze it, you must root the device.

Due to these context restrictions, untrusted applications cannot easily execute native binaries stored in the assets directory. This post references a [Reddit thread](https://www.reddit.com/r/androiddev/comments/193imrb/executing_compiled_c_binary_in_mobile_app_without/) and documents how to execute a native binary using the `jniLibs` directory on Android 16 (tested on Google Pixel 8a).

## How To

Intuitively, you might think that placing a precompiled native binary in `assets` directory, extracting it at runtime to the app's private directory (`/data/user/0/com.example.myapplication/`), and setting the executable bit would allow you to run it. However, testing shows that even if the file is marked as executable, running it still results in a **Permission denied** error.

The workaround is to first add the `extractNativeLibs` attribute in your `AndroidManifest.xml`, which causes `.so` files in the APK to be extracted to the filesystem:

``` diff
     <application
         android:allowBackup="true"
         android:dataExtractionRules="@xml/data_extraction_rules"
         android:fullBackupContent="@xml/backup_rules"
         android:icon="@mipmap/ic_launcher"
         android:label="@string/app_name"
         android:roundIcon="@mipmap/ic_launcher_round"
         android:supportsRtl="true"
         android:theme="@style/Theme.MyApplication"
+        android:extractNativeLibs="true"
```

Then rename your native binary to follow the `libXXXXX.so` format to ensure it is extracted. Next, create a `jniLibs` directory and add a subdirectory based on the architecture. For example, for ARM64, use `arm64-v8a`. Place the binary in that subdirectory. The resulting directory layout should look like:

```
app/src/main/jniLibs
             └── arm64-v8a
                 └── libtest.so
```

In your application, use `context.applicationInfo.nativeLibraryDir` [1] to get the runtime path of `jniLibs`. Then, you can execute the uploaded native binary using `ProcessBuilder()` [2]:

``` kotlin
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BinaryRunnerUI() {
    val context = LocalContext.current
    var outputText by remember { mutableStateOf("Press button to execute binary") }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Binary Executor") }
            )
        }
    ) { paddingValues ->
        Column(modifier = Modifier.padding(paddingValues)) {
            Button(onClick = {
                val libPath: String = context.applicationInfo.nativeLibraryDir // [1]
                outputText = runBinary(libPath)
            }) {
                Text("Execute binary")
            }
            Text(outputText, modifier = Modifier.padding(16.dp))
        }
    }
}

fun runBinary(libPath: String): String {
    return try {
        val process = ProcessBuilder("sh", "-c", "$libPath/libtest.so") // [2]
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()

        "Output:\n$output\n"
    } catch (e: Exception) {
        "Failed: ${e.message}"
    }
}
```

However, while this method works, it seems that `untrusted_app` context restricts certain syscalls that glibc tries to invoke during initialization. As a result, running a statically compiled native binary may return a **Bad system call** error.
