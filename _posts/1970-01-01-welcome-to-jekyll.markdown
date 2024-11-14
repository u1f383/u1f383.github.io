---
layout: post
title:  "Welcome to Jekyll!"
categories: cheatsheet
---

## kernelCTF

### VM setup
``` bash
# 1. Get VM script
https://github.com/google/security-research/blob/88077ea2e1beaa17107cd9d7ee6beb97faa6468e/kernelctf/simulator/local_runner.sh

# 2. Update qemu script
-fsdev local,id=test_dev,path=<PATH_OF_SHARED_FOLDER>,security_model=none \
-device virtio-9p-pci,fsdev=test_dev,mount_tag=test_mount \

# 3. Mount 9pfs
## 3.1 unpack the ramdisk
gunzip ramdisk_v1.img

## 3.2 append the following line to file "/init"
mount -t 9p -o trans=virtio -o version=9p2000.L test_mount ${rootmnt}/chroot/mnt

## 3.3 pack back ramfs cpio
find . -print0 | cpio --null --owner=root -o --format=newc > ../ramdisk_v1.img
```

### Information
``` bash
# Kernel image (bzImage)
wget https://storage.googleapis.com/kernelctf-build/releases/lts-X.X.X/bzImage

# Kernel image (vmlinux)
wget https://storage.googleapis.com/kernelctf-build/releases/lts-X.X.X/vmlinux.gz

# Kernel config
wget https://storage.googleapis.com/kernelctf-build/releases/lts-X.X.X/.config

# Source code info
curl https://storage.googleapis.com/kernelctf-build/releases/lts-X.X.X/COMMIT_INFO
wget https://github.com/gregkh/linux/archive/<COMMIT_HASH>.zip
```

### Compilation

``` bash
# compile x64 version on aarch64
make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -j`nproc`
```


## Debug

``` bash
gdb-multiarch ./vmlinux -ex "target remote :1234"
```

### GDB Stub
``` bash
# breakpoint at specific syscall
b __do_sys_<SYSCALL_NAME>

# breakpoint at syscall entry
b entry_SYSCALL_64
```