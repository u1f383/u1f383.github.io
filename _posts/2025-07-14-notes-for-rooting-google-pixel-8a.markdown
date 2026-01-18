---
layout: post
title:  "Notes for Rooting Google Pixel 8a"
categories: Android
---

I made some notes while rooting my Google Pixel 8a and shared them here. Most parts are based on [leland's blog](https://leland.zip/pixel9/pixel9.html), which is worth reading.

## 1. Prerequisites

1. Enable Developer Options:
    - Go to `Settings` > `About phone`
    - Tap Build number 7 times until developer mode is enabled
2. Return to the main `Settings` menu > `Developer` options, and enable:
    - OEM unlocking (required to unlock the bootloader)
    - USB debugging


## 2. Unlock the Bootloader

> This will factory reset your device, so please backup first.

1. Reboot into Fastboot mode:
    ``` bash
    $ adb reboot bootloader
    ```

2. Check device connection:
    ``` bash
    $ fastboot devices
    ```

3. Unlock the bootloader:
    ``` bash
    $ fastboot flashing unlock
    ```
    - Your phone will display a warning. Use the volume keys to select `Unlock the bootloader`, then confirm with the power button.

4. After unlocking, Fastboot mode will show:
    ```
    [...]
    Device state: unlocked
    [...]
    ```

5. The phone will reboot and reset. Go through the setup process again.

## 3. Flash a Specific Factory Image
> You only need to perform steps 1–4 if your target version matches the one shown on your device.

1. Go to `Settings` > `About phone`, and note the current version (e.g., **`BP31.250523.006`**)
2. Download the factory image from the official Google site:
    - [release](https://developers.google.com/android/images?hl=zh-tw)
    - [beta](https://developer.android.com/about/versions/16/download?utm_source&hl=zh-tw)
    - [mapping for release ID (e.g., BP3A.250905.014) and release tag (e.g., android-16.0.0_r3)](https://source.android.com/docs/setup/reference/build-numbers?hl=zh-tw)
    - Please download the factory image that matches the corresponding device codename.
        - For example, the codename for the **Pixel 8a** is **akita**.
    - Target version used here: **`BP2A.250705.008`**
3. Verify the SHA-256 checksum:
    ``` bash
    $ sha256sum akita-bp2a.250705.008-factory-80be6c76.zip
    80be6c762c41f3c8c92d55486370f8367fdb2a292440e2ac6fca73ba9bd2d883  akita-bp2a.250705.008-factory-80be6c76.zip
    ```
4. Unzip the factory image:
    ``` bash
    $ unzip akita-bp2a.250705.008-factory-80be6c76.zip
    ```
    Directory tree:
    ```
    akita-bp2a.250705.008
    ├── bootloader-akita-akita-16.2-13291556.img
    ├── d3m2.ec.bin
    ├── evt.ec.bin
    ├── flash-all.bat
    ├── flash-all.sh
    ├── flash-base.sh
    ├── image-akita-bp2a.250705.008.zip
    ├── proto11.ec.bin
    └── radio-akita-g5300o-250320-250425-b-13407682.img
    ```
5. Flash the factory image:
    ``` bash
    $ adb reboot bootloader

    # Wait for the phone to enter Fastboot mode
    $ ./flash-all.sh
    ```
    - Your phone will reboot multiple times during this process, and the host terminal will display progress messages.

6. After flashing, set up your phone again.

## 4. Install Magisk and Root the Device

[Magisk](https://github.com/topjohnwu/Magisk) is a popular systemless root tool for Android, which I used to root my Pixel 8a.

1. Download Magisk APK from [its GitHub repo](https://github.com/topjohnwu/Magisk/releases)
2. Install the APK:
    ``` bash
    adb install Magisk-v30.1.apk
    ```
    - The version number may vary.
3. Extract `init_boot.img` from `image-akita-*.zip`:
    ``` bash
    $ unzip image-akita-bp2a.250705.008.zip
    # [...]

    $ file init_boot.img
    init_boot.img: Android bootimg, kernel
    ```
4. Push `init_boot.img` to your phone:
    ``` bash
    $ adb push init_boot.img /sdcard/Download/
    ```
5. Open the Magisk app:
    - Tap `Install` icon
    - Choose `Select and Patch a File`
    - Navigate to the `Download` folder and select `init_boot.img`
6. Magisk will generate a patched image:
    ``` bash
    $ adb shell ls -al /sdcard/Download/
    total 16400
    -rw-rw---- 1 u0_a269 media_rw 8388608 2009-01-01 00:00 init_boot.img
    -rwxrwx--- 1 u0_a269 media_rw 8388608 2025-07-14 15:53 magisk_patched-30100_mTu65.img
    ```
    - Note: The suffix of the patched file name is random.
7. Pull the patched image back to your computer:
    ``` bash
    $ adb pull /sdcard/Download/magisk_patched-30100_mTu65.img
    ```
8. Reboot into Fastboot and flash the patched `init_boot.img`:
    ``` bash
    $ adb reboot bootloader
    $ fastboot flash init_boot magisk_patched-30100_mTu65.img

    fastboot flash init_boot magisk_patched-30100_mTu65.img
    Sending 'init_boot_b' (8192 KB)                    OKAY [  0.189s]
    Writing 'init_boot_b'                              OKAY [  0.021s]
    Finished. Total time: 0.215s
    ```
9. Reboot your phone:
    ``` bash
    $ fastboot reboot
    ```

## 5. Verify Root Access

1. Once booted, open the Magisk app — it should show that Magisk is installed.
2. On your computer, enter:
    ``` bash
    $ adb shell
    akita:/ $ su
    akita:/ # id
    uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
    ```
    - A prompt will appear on your phone — tap `Allow` to grant root access.

## 6. Extract Binary From Image

Android doesn't allow users to downgrade to an older version, so the only way to retrieve older binaries is from an image file.

``` bash
$ file system_ext.img
system_ext.img: Linux rev 1.0 ext2 filesystem data, UUID=d3dc357b-9d8c-57f3-af38-1dda11821d01, volume name "system_ext" (extents) (large files) (huge files)
```

However, you may encounter issues when trying to mount it on an Ubuntu VM:

``` bash
$ sudo mount system_ext.img mnt
mount: /tmp/mnt: wrong fs type, bad option, bad superblock on /dev/loop6, missing codepage or helper program, or other error.
       dmesg(1) may have more information after failed mount system call.

$ dmesg
[679270.016567] loop6: detected capacity change from 0 to 552272
[679270.024279] EXT4-fs (loop6): couldn't mount RDWR because of unsupported optional features (4000)
```

This happens because Ubuntu doesn’t support the large directory feature (0x4000).

To work around this, you can use **debugfs**, an interactive file system debugger, to view and extract files instead of mounting the image:

``` bash
debugfs system_ext.img
dump /bin/hw/vendor.google.edgetpu_app_service@1.0-service ./old_edgetpu_app_service
```