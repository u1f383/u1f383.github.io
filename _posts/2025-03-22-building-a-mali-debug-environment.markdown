---
layout: post
title:  "Building a Mali GPU Debug Environment"
categories: android
---

Just a quick note on how I set up my Mali debug environment. Most of this post references [this issue](https://project-zero.issues.chromium.org/issues/42451673), submitted by Jann Horn.

My host is based on aarch64, while the VM runs on x86_64.

## Step1. Download Mali Driver

Go to the official website and download the latest Mali driver source code (you might need to register first):
- [link](https://developer.arm.com/downloads/-/Valhall%20Mali%204th%20Gen%20GPU%20Architecture)

After unpacking the archive, you'll see a bunch of files, but we only care about these two directories:
- `src/product/kernel/include` - header files
- `src/product/kernel/drivers/gpu/arm` - Mali driver source files

## Step2. Download Your Kernel

I'm using Linux kernel version 6.1.73 for this setup.

``` bash
wget https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.1.73.tar.gz
# ...
make defconfig
```

## Step3. Patch

### Configuration

`kernel_src/drivers/gpu/Makefile` - enable building the `arm/` directory by adding it to `obj-y`:
``` diff
 obj-y           += host1x/ drm/ vga/
+obj-y           += arm/
 obj-$(CONFIG_IMX_IPUV3_CORE)    += ipu-v3/
 obj-$(CONFIG_TRACE_GPU_MEM)     += trace
```

`kernel_src/drivers/Kconfig` - include the Mali driver's `Kconfig` so we can configure it via menuconfig:
```diff
 source "drivers/android/Kconfig"

 source "drivers/gpu/trace/Kconfig"
+source "drivers/gpu/arm/Kconfig"
```

`.config` - manually add the following lines to the end of your `.config` file:

```
CONFIG_MALI_MIDGARD=y
CONFIG_MALI_PLATFORM_NAME="vexpress"
CONFIG_MALI_NO_MALI=y
CONFIG_MALI_NO_MALI_DEFAULT_GPU="tKRx"  
CONFIG_MALI_CSF_SUPPORT=y
CONFIG_MALI_DEVFREQ=y
CONFIG_MALI_GATOR_SUPPORT=y
CONFIG_MALI_EXPERT=y
CONFIG_MALI_VECTOR_DUMP=y
CONFIG_MALI_PRFCNT_SET_PRIMARY=y
CONFIG_MALI_TRACE_POWER_GPU_WORK_PERIOD=y

CONFIG_SYNC_FILE=y

# make sure `CONFIG_OF` is disabled, or `/dev/mali0` won't show up.
CONFIG_OF=n
```

Run `make olddefconfig` to populate the configuration update.

### Source Code

Now, copy the relevant Mali source and headers into the kernel tree:

``` bash
## [1] Source files
cp -r driver_src/driver/product/kernel/drivers/gpu/arm kernel_src/drivers/gpu/

## [2] Header files
cp -r driver_src/driver/product/kernel/include/linux/* kernel_src/include/linux/
cp -r driver_src/driver/product/kernel/include/uapi/* kernel_src/include/uapi/
```

Create a few files and directories that are referenced but missing:

``` bash
# [1] arm/aarch64-specific header (hack for x86 build)
touch kernel_src/arch/x86/include/asm/arch_timer.h

# [2] Avoid the complaints during cleanup
mkdir kernel_src/drivers/gpu/arm/arbitration/
touch kernel_src/drivers/gpu/arm/arbitration/Makefile
```

Some Mali code expects ARM-specific hardware, so we'll patch those parts to avoid build issues on x86.

`kernel_src/drivers/gpu/arm/midgard/csf/mali_kbase_csf.c`

``` diff
+ #define dmb(...) do {} while (0)
```

`kernel_src/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_time.c`

``` diff
u64 kbase_arch_timer_get_cntfrq(struct kbase_device *kbdev)
{
-   u64 freq = mali_arch_timer_get_cntfrq();
+   u64 freq = 1000;
    dev_dbg(kbdev->dev, "System Timer Freq = %lluHz", freq);
    return freq;
}
```

`kernel_src/drivers/gpu/arm/midgard/mali_kbase_core_linux.c`

``` diff
void power_control_term(struct kbase_device *kbdev)
{
    // [...]
    for (i = 0; i < BASE_MAX_NR_CLOCKS_REGULATORS; i++) {
        if (kbdev->clocks[i]) {
+           //if (__clk_is_enabled(kbdev->clocks[i]))
+           //  clk_disable_unprepare(kbdev->clocks[i]);
            clk_put(kbdev->clocks[i]);
            kbdev->clocks[i] = NULL;
        } else
    // [...]
```

#### In some situations

Comment out these function definitions:
- `kbasep_devfreq_read_suspend_clock()` (in `drivers/gpu/arm/midgard/backend/gpu/mali_kbase_devfreq.c`)
- `pcm_prioritized_process_cb()` (in `drivers/gpu/arm/midgard/device/mali_kbase_device.c`)

Apply patch for `kernel_src/include/linux/version_compat_defs.h`:

``` diff                                                                
-static inline int of_property_check_flag(const struct property *p, unsigned long flag)       
-{                                                                                            
-       return -EINVAL;                                                                       
-}                                                                                            
-                                                                                             
-static inline void of_property_set_flag(struct property *p, unsigned long flag)              
-{                                                                                            
-}                                                                                            
-                                                                                             
-static inline void of_property_clear_flag(struct property *p, unsigned long flag)            
-{                                                                                            
-}                                                                                            
+//static inline int of_property_check_flag(const struct property *p, unsigned long flag)     
+//{                                                                                          
+//     return -EINVAL;                                                                       
+//}                                                                                          
+//                                                                                           
+//static inline void of_property_set_flag(struct property *p, unsigned long flag)            
+//{                                                                                          
+//}                                                                                          
+//                                                                                           
+//static inline void of_property_clear_flag(struct property *p, unsigned long flag)          
+//{                                                                                          
+//}                                                                                                                                                       
```

Copy all in one:

``` bash
#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <driver_src> <kernel_src>"
    exit 1
fi

driver_src=$1
kernel_src=$2

echo "Copying files from $driver_src to $kernel_src..."

cp -r "$driver_src/product/kernel/drivers/gpu/arm" "$kernel_src/drivers/gpu/"
cp -r "$driver_src/product/kernel/include/linux/"* "$kernel_src/include/linux/"
cp -r "$driver_src/product/kernel/include/uapi/"* "$kernel_src/include/uapi/"

touch "$kernel_src/arch/x86/include/asm/arch_timer.h"

mkdir -p "$kernel_src/drivers/gpu/arm/arbitration/"
touch "$kernel_src/drivers/gpu/arm/arbitration/Makefile"
```

## Step4. Compile

Cross compile:

``` bash
# [1] Propagate Mali-related config options
make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -j`nproc` oldconfig

# [2] Compile the x86_64 kernel
make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -j`nproc`
```

## Step5. Run VM

Here's the QEMU script I use:

``` bash
#!/bin/bash
exec qemu-system-x86_64 -m 2G -nographic -no-reboot \
  -monitor none \
  -smp cores=2 \
  -kernel ./src/arch/x86/boot/bzImage \
  -initrd ramdisk_v1.img \
  -nic user,model=virtio-net-pci \
  -drive file=rootfs_v3.img,if=virtio,cache=none,aio=native,format=raw,discard=on,readonly \
  -fsdev local,id=test_dev,path=/media/psf/shared_folder/GPU_research,security_model=none \
  -device virtio-9p-pci,fsdev=test_dev,mount_tag=test_mount \
  -append "nokaslr console=ttyS0 root=/dev/vda1 rootfstype=ext4 rootflags=discard ro init=/bin/bash hostname=Mali" -s
```

I reuse my kernelCTF ramdisk, but it's ok to build your own filesystem using [Buildroot](https://buildroot.org):

``` bash
wget https://buildroot.org/downloads/buildroot-2024.02.11.tar.gz
# ...
make menuconfig
# ...
make -j`nproc`
```

Some important Buildroot options:

```
# Target options
Target Architecture (x86_64)

# Filesystem images
ext2/3/4 root filesystem (ext4)
```

Modify the rootfs of kernelCTF image:
``` bash
$ file rootfs_v3.img
rootfs_v3.img: DOS/MBR boot sector; partition 1 : ID=0x83, active, start-CHS (0x0,32,33), end-CHS (0x2a,42,32), startsector 2048, 8386560 sectors

# 1048576 = 2048 (startsector) * 512 (sector size)
$ sudo mount -o loop,offset=1048576 rootfs_v3.img rootfs

$ touch rootfs/chroot/dev/mali0
```

Patch for `rootfs/home/user/nsjail.cfg`:
``` diff
   {
     src: "/dev/random"
     dst: "/dev/random"
     is_bind: true
     rw: true
   },
+  {
+    src: "/dev/mali0"
+    dst: "/dev/mali0"
+    is_bind: true
+    rw: true
+  },
   {
     src: "/dev/full"
     dst: "/dev/full"
     is_bind: true
     rw: true
   },
```

## Reference

- [MALI_NO_MALI](https://www.c1n.org/2024/10/12/mali_no_mali/)
- [Mali G610 Reverse Engineering, Part 1](https://icecream95.gitlab.io/mali-g610-reverse-engineering-part-1.html)
- [Arm Mali 5th Gen: dangling ATE via short alias of large page](https://project-zero.issues.chromium.org/issues/42451673)
