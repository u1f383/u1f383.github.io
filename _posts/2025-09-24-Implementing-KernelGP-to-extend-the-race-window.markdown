---
layout: post
title:  "Implementing KernelGP to Extend the Race Window"
categories: Android
---

The talk [KernelGP: Racing Against the Android Kernel](https://www.youtube.com/watch?v=DJBGu2fSSZg) at OffensiveCon 2025 demonstrates four techniques to leverage Android’s internal design to extend the race window during kernel exploitation. In this post, I will walk through my exploration of the **first method** — **the proxy file descriptor** — and explain how I implemented it. I’ll also share some side notes on writing an Android app.

## 1. JNI

### 1.1. Introduction

JNI (Java Native Interface) is an interface between Java/Kotlin applications and C/C++ libraries. It allows developers to write C libraries and load them into applications. This is very useful in exploitation development, because applications are written in high-level languages, where we lack fine-grained control over operations.

To write a library, you first need to [download the NDK](https://developer.android.com/ndk/downloads?hl=zh-tw). It includes toolchains for building libraries, most of which are pre-built, so no additional compilation is required. I used `android-ndk-r27d-linux.zip` in my virtual machine.

Once uncompressed, you can use JNI APIs to write a library. For example, here is a **`hello.c`** that implements a simple JNI function returning a `"Hello World"` string:

```c
#include <jni.h>

JNIEXPORT jstring JNICALL
Java_com_example_myapplication_MainActivity_stringFromJNI(JNIEnv* env, jobject thiz) {
    return (*env)->NewStringUTF(env, "Hello from C!");
}
```

The function name cannot be arbitrary — it must follow JNI naming conventions. The format is: **`Java_<application_name>_<class_name>_<method_name>`** with dots (`.`) in names replaced by underscores (`_`), and underscores (`_`) further escaped as `_1`.

The first two parameters are predefined: the **JNI environment object (`env`)** and the **caller object (`thiz`)**. The return type must be a Java-compatible type, such as `void`, `jboolean`, `jint`, `jstring`, etc.

To compile it, use the toolchain compiler with flags for building a shared object:

``` bash
~/android-ndk-r27d/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang -shared -fPIC -o libhello.so hello.c
```

Then, copy `libhello.so` to `~/path_to_your_application/app/src/main/jniLibs/arm64-v8a/`.

In the `com.example.myapplication` project, you need to add the attribute **`android:extractNativeLibs="true"`** in `AndroidManifest.xml` to ensure the application extracts native shared objects:

```
<application
    [...]
    android:extractNativeLibs="true"
>
```

The `MainActivity` class then uses `System.loadLibrary()` to load the shared library. The file name must **follow the format `"libXXXXX.so"`**, otherwise it will not be extracted and cannot be loaded. You also need to declare an external function for later use:

```
init { System.loadLibrary("hello") }
external fun helloworld(): String
```

Now, you can call `helloworld()` anywhere in your application!

### 1.2. Real JNI

The actual library **`libfuse_mmap.so`** used to trigger FUSE is shown below:

``` c
#include <jni.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>

char buf[0x100];
JNIEXPORT jstring JNICALL
Java_com_example_fuse_1test_MainActivity_mmapfuse(JNIEnv* env, jobject thiz, jint fd /* [1] */) {
    void* ptr = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, fd, 0); // [2]
    if (ptr == MAP_FAILED) {
        char buf[128];
        snprintf(buf, sizeof(buf), "mmap failed: errno=%d (%s)", errno, strerror(errno));
        return (*env)->NewStringUTF(env, buf);
    }
    memset(buf, 'A', sizeof(buf));
    memcpy(buf, ptr, 0x10); // [3]
    return (*env)->NewStringUTF(env, buf);
}
```

This function is called `mmapfuse()` and belongs to the `MainActivity` class in the `com.example.fuse_test` project. It takes the FUSE file descriptor as a parameter [1] and maps it into the process address space with `mmap()` [2]. When `memcpy()` reads from the mapped memory [3], **page fault will be handled by the FUSE handler**.

## 2. App

The following is the source code of the application **`com.example.fuse_test`**. I will explain it line by line.

``` java
class MainActivity : ComponentActivity() {
    // =============== [1] ===============
    init { System.loadLibrary("fuse_mmap") }
    external fun mmapfuse(fuseFd: Int): String
    // ===================================

    override fun onCreate(savedInstanceState: Bundle?) { // [2]
        super.onCreate(savedInstanceState)
        setContent {
            // =============== [3] ===============
            var output by remember { mutableStateOf("running...") }
            var fusePfd by remember { mutableStateOf<ParcelFileDescriptor?>(null) }
            var callbackThread by remember { mutableStateOf<HandlerThread?>(null) }
            var callbackHandler by remember { mutableStateOf<Handler?>(null) }
            // ===================================

            LaunchedEffect(Unit) { // [4]
                callbackThread = HandlerThread("ProxyFDCallbacks").apply { start() } // [6]
                callbackHandler = Handler(callbackThread!!.looper)
                val data = "from FUSE callback :)".toByteArray(Charsets.UTF_8)
                val sm = getSystemService(STORAGE_SERVICE) as StorageManager // [7]
                
                fusePfd = sm.openProxyFileDescriptor( // [8]
                    ParcelFileDescriptor.MODE_READ_ONLY,
                    FuseCallback(data),
                    callbackHandler
                )
                output = mmapfuse(fusePfd!!.fd) // [11]
            }

            Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                Text(output, modifier = Modifier.padding(innerPadding)) // [12]
            }

            DisposableEffect(Unit) { // [5]
                onDispose {
                    try { fusePfd!!.close() } catch (_: Exception) {}
                    callbackThread!!.quitSafely()
                }
            }
        }
    }
}

class FuseCallback(private val data: ByteArray) : ProxyFileDescriptorCallback() { // [9]
    override fun onGetSize(): Long = data.size.toLong()
    override fun onRead(offset: Long, size: Int, dst: ByteArray): Int {
        if (offset < 0 || size < 0) throw ErrnoException("onRead", OsConstants.EINVAL)
        if (offset >= data.size) return 0
        val n = minOf(size, data.size - offset.toInt())
        System.arraycopy(data, offset.toInt(), dst, 0, n)
        Thread.sleep(2000) // [10]
        return n
    }
    override fun onWrite(offset: Long, size: Int, data: ByteArray): Int {
        throw ErrnoException("onWrite", OsConstants.EBADF)
    }
    override fun onFsync() {}
    override fun onRelease() {}
}
```

First, we load the **shared library `libfuse_mmap.so`** and **function `mmapfuse()`** [1] which was implemented in **section 1.2**.

Once the application is loaded, the `onCreate()` method is invoked [2], so it can be considered the entry point of the application. Next, we define several mutable variables to maintain state within a Composable by keywork `remember` [3].

After that, we use `LaunchedEffect(Unit)` [4] and `DisposableEffect(Unit)` [5] to define the prologue and epilogue handlers when entering and leaving the Composition.

The prologue handler **creates a thread `"ProxyFDCallbacks"` as a proxy fd handler** [6], since the proxy fd must be managed on a separate thread. Then, the `getSystemService()` function [7] is called to obtain the `StorageManager` system service. Using this handle, we can **communicate with the storage manager service** and request it to create a proxy fd for us by **calling the `openProxyFileDescriptor()` function** [8].

This function takes three parameters: **opened file mode**, **callback object** and **handling thread**. Since the file mode is set to `ParcelFileDescriptor.MODE_READ_ONLY`, we can only read the file but cannot write to it. The `FuseCallback()` [9] class extends the callback handler to provide custom behavior.

In the `onRead()` handler, we **insert a sleep call** [10] before returning the read size. As a result, when `mmapfuse()` [11] is invoked, the memory copy operation — **specifically `memcpy(buf, ptr, 0x10)`** — on the mapped FUSE fd **will block the read access for two seconds**.

Later, the output of the function call is displayed on the screen by invoking `Text()` [12], which is expected to look like:

<img src="/assets/image-20250924143618063.png" alt="image-20250924143618063" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

Finally, the epilogue closes the FUSE fd and releases the `"ProxyFDCallbacks"` thread.

## 3. Internal

According to the [API documentation](https://developer.android.com/reference/android/content/Context#getSystemService(java.lang.String)), we can call `getSystemService()` to obtain a handle to a system-level service by name. This allows us to retrieve a `StorageManager` instance and access its predefined handlers.

``` java
public abstract Object getSystemService (String name)
```

The `StorageManager` class provides the method `openProxyFileDescriptor()`, which is implemented in [android.os.storage.StorageManager](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/os/storage/StorageManager.java;l=2019?q=registerStorageVolumeCallback&ss=android).

``` java
@SystemService(Context.STORAGE_SERVICE)
public class StorageManager {
    // [...]
    
    public @NonNull ParcelFileDescriptor openProxyFileDescriptor(
            int mode, ProxyFileDescriptorCallback callback, Handler handler)
                    throws IOException {
        Preconditions.checkNotNull(handler);
        return openProxyFileDescriptor(mode, callback, handler, null);
    }
    
    // [...]
}
```

Internally, the method `mountProxyFileDescriptorBridge()` [1] is invoked to obtain an `AppFuseMount` object and enter the FUSE app loop to handle file operations.

``` java
public @NonNull ParcelFileDescriptor openProxyFileDescriptor(
        int mode, ProxyFileDescriptorCallback callback, Handler handler, ThreadFactory factory)
                throws IOException {
    // [...]
    while (true) {
        try {
            synchronized (mFuseAppLoopLock) {
                boolean newlyCreated = false;
                if (mFuseAppLoop == null) {
                    final AppFuseMount mount = mStorageManager.mountProxyFileDescriptorBridge(); // [1]
                }
                // [...]
                mFuseAppLoop = new FuseAppLoop(mount.mountPointId, mount.fd, factory);
                // [...]
            }
            // [...]
        }
    }
    // [...]
}
```

This call corresponds to a Binder transaction in `IStorageManager`, as defined in [IStorageManager.aidl](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/os/storage/IStorageManager.aidl?q=mountProxyFileDescriptorBridge&ss=android%2Fplatform%2Fsuperproject%2Fmain). The `IStorageManager` service **runs inside `system_server`**, which hosts almost all of the **core system services**.

```
interface IStorageManager {
    // [...]
    AppFuseMount mountProxyFileDescriptorBridge() = 73;
    // [...]
}
```

We can verify this information using the `service` and `ps` shell commands.

```
akita:/ # service list | grep mount
242	mount: [android.os.storage.IStorageManager]

akita:/ # ps -A | grep -i system_server
system        1436   903   23594364 775776 do_epoll_wait       0 S system_server
```

The method `mountProxyFileDescriptorBridge()` is implemented in [StorageManagerService.java](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/StorageManagerService.java;l=3754?q=mountProxyFileDescriptorBridge&ss=android%2Fplatform%2Fsuperproject%2Fmain), where it creates an `AppFuseMountScope` object [2].

``` java
class StorageManagerService extends IStorageManager.Stub
        implements Watchdog.Monitor, ScreenObserver {
    // [...]
    
    @Override
    public @Nullable AppFuseMount mountProxyFileDescriptorBridge() {
        // [...]
        while (true) {
            // [...]
            try {
                return new AppFuseMount(
                    name, mAppFuseBridge.addBridge(new AppFuseMountScope(uid, name))); // [2]
            } catch (FuseUnavailableMountException e) {
                // [...]
            }
        }
    }

    // [...]
}
```

The `AppFuseMountScope` class is also defined in [StorageManagerService.java](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/StorageManagerService.java;l=3693?q=AppFuseMountScope&ss=android%2Fplatform%2Fsuperproject%2Fmain). Its `open()` method eventually calls `mVold.mountAppFuse()` [3] to obtain the FUSE fd.

``` java
class AppFuseMountScope extends AppFuseBridge.MountScope {
        private boolean mMounted = false;

    public AppFuseMountScope(int uid, int mountId) {
        super(uid, mountId);
    }

    @Override
    public ParcelFileDescriptor open() throws AppFuseMountException {
        extendWatchdogTimeout("#open might be slow");
        try {
            final FileDescriptor fd = mVold.mountAppFuse(uid, mountId); // [3]
            mMounted = true;
            return new ParcelFileDescriptor(fd);
        } catch (Exception e) {
            throw new AppFuseMountException("Failed to mount", e);
        }
    }
    // [...]
}
```

The method `mountAppFuse()` is a Binder call exposed by the Vold (Volume Daemon) process, defined in [IVold.aidl](https://cs.android.com/android/platform/superproject/main/+/main:system/vold/binder/android/os/IVold.aidl;l=80?q=mountAppFuse&ss=android%2Fplatform%2Fsuperproject%2Fmain).

```
@SensitiveData
interface IVold {
    FileDescriptor mountAppFuse(int uid, int mountId);
}
```

Vold runs as a dedicated process, which is responsible for handling the FUSE open and mount operations internally:

```
akita:/ # service list | grep -i vold
# [...]
368	vold: [android.os.IVold]

akita:/ # ps -A | grep -i vold
root           559     1   11025252   9996 binder_thread_read  0 S vold
```


Finally, within the C++ function [`MountAppFuse()`](https://cs.android.com/android/platform/superproject/main/+/main:system/vold/AppFuseUtil.cpp;l=105?q=mountAppFuse&ss=android%2Fplatform%2Fsuperproject%2Fmain), the mount path is defined [4], the **`"/dev/fuse"`** file is opened [5], and the mount operation [6] is performed.

``` c
int MountAppFuse(uid_t uid, int mountId, android::base::unique_fd* device_fd) {
    std::string name = std::to_string(mountId);

    // [...]
    std::string path;
    // [...]
    if (GetMountPath(uid, name, &path) != android::OK) { // [4]
        LOG(ERROR) << "Invalid mount point name";
        return -1;
    }
    // [...]
    device_fd->reset(open("/dev/fuse", O_RDWR)); // [5]
    // [...]
    return RunCommand("mount", uid, path, device_fd->get()); // [6]
}
```