---
layout: post
title:  "Linux I/O Port Access Checks on x86_64"
categories: Linux
---

While reading the article [Kernel Blues, or Why x86 Is So Convoluted](https://thekidofarcrania.gitlab.io/2020/07/19/kernel-blues/), I realized that my understanding of the restrictions on I/O port access in x86-64 was still incomplete. This post is therefore intended to document my thought process and analysis.

### 1. Introduction

The CPU generally interacts with I/O devices in two ways: **I/O ports** and **MMIO (Memory-Mapped I/O)**.
- The former uses instructions such as `in` and `out` to directly access I/O ports.
- The latter maps a region of device memory into the system’s address space, allowing the device to be controlled just like regular memory.

Access protection for MMIO relies on the same mechanisms used for memory, whereas I/O port access is governed by a separate set of rules.

Take the [`out`](https://www.felixcloutier.com/x86/out) instruction as an example. When executing this instruction to write to an I/O port, the hardware performs the following checks:

```
IF ((PE = 1) and ((CPL > IOPL) or (VM = 1)))
    THEN (* Protected mode with CPL > IOPL or virtual-8086 mode *)
        IF (Any I/O Permission Bit for I/O port being accessed = 1)
            THEN (* I/O operation is not allowed *)
                #GP(0);
            ELSE ( * I/O operation is allowed *)
                DEST := SRC; (* Writes to selected I/O port *)
        FI;
    ELSE (Real Mode or Protected Mode with CPL ≤ IOPL *)
        DEST := SRC; (* Writes to selected I/O port *)
FI;
```
Key fields involved in the check:
- **PE (Protected Mode Enable)**: `CR0.PE`.
	- A value of 1 means protected mode is enabled. Normally, this is set to 1.
- **CPL (Current Privilege Level)**: determined by the lowest 2 bits of the `CS` (Code Segment Selector).
	- 0 is the highest privilege (kernel space), while 3 is the lowest (user space).
- **IOPL (I/O Privilege Level)**: `EFLAGS.IOPL`.
	- If not explicitly configured, this value is typically 0 in both user and kernel space.
- **VM (Virtual 8086 Mode)**: `EFLAGS.VM`.
	- A value of 1 means virtual-8086 mode is active. Normally, this is 0.
- I/O Permission Bit: found in the I/O bitmap within the `TSS` (Task State Segment).

The registers themselves are relatively straightforward. But what exactly is the **_I/O Permission Bit_**? And how do we configure this field?

## 2. iopl

The `SYS_iopl` system call can be used to update a process’ I/O port access permissions. At a high level, this syscall performs two main tasks:
1. Updates the `current->iopl_emul` field [1]
2. Set the `TIF_IO_BITMAP` of task [2]

``` c
SYSCALL_DEFINE1(iopl, unsigned int, level)
{
    struct thread_struct *t = &current->thread;
    // [...]
    t->iopl_emul = level; // [1]
    task_update_io_bitmap(current);
    // [...]
}

static void task_update_io_bitmap(struct task_struct *tsk)
{
    struct thread_struct *t = &tsk->thread;

    if (t->iopl_emul == 3 || t->io_bitmap) {
        set_tsk_thread_flag(tsk, TIF_IO_BITMAP); // [2]
    } 
    // [...]
}

static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
    set_ti_thread_flag(task_thread_info(tsk), flag);
}

# define task_thread_info(task) (&(task)->thread_info)
static inline void set_ti_thread_flag(struct thread_info *ti, int flag)
{
    set_bit(flag, (unsigned long *)&ti->flags);
}
```

Before returning from the syscall handler to user space, the kernel checks whether the task’s flags include `_TIF_IO_BITMAP` [3]. If so, it updates the I/O bitmap. In the case where `t->iopl_emul` = 3, the kernel additionally updates the bitmap base [4].

``` c
static void exit_to_user_mode_prepare(struct pt_regs *regs)
{
    ti_work = read_thread_flags();
    // [...]
    arch_exit_to_user_mode_prepare(regs, ti_work); // <------------
    // [...]
}

#define read_thread_flags() \
    read_ti_thread_flags(current_thread_info())

static inline void arch_exit_to_user_mode_prepare(struct pt_regs *regs,
                          unsigned long ti_work)
{
    if (unlikely(ti_work & _TIF_IO_BITMAP)) // [3]
        tss_update_io_bitmap(); // <------------
}

#define tss_update_io_bitmap native_tss_update_io_bitmap
void native_tss_update_io_bitmap(void)
{
    struct tss_struct *tss = this_cpu_ptr(&cpu_tss_rw);
    struct thread_struct *t = &current->thread;
    u16 *base = &tss->x86_tss.io_bitmap_base;
    // [...]
    if (IS_ENABLED(CONFIG_X86_IOPL_IOPERM) && t->iopl_emul == 3) {
        *base = IO_BITMAP_OFFSET_VALID_ALL; // [4]
    } 
    // [...]
}
```

In the **TSS (Task State Segment)**, the `io_bitmap_base` field points to the offset of the active I/O Permission Bitmap within the TSS. During CPU initialization, the kernel sets up the TSS bitmap [5] and loads the address of the TSS structure into the task register [6].

``` c
void cpu_init_exception_handling(void)
{
    struct tss_struct *tss = this_cpu_ptr(&cpu_tss_rw);
    int cpu = raw_smp_processor_id();
    // [...]
    tss_setup_io_bitmap(tss); // [5]
    set_tss_desc(cpu, &get_cpu_entry_area(cpu)->tss.x86_tss); // [6]
    // [...]
}
```

The function `tss_setup_io_bitmap()` sets the bitmap base to `IO_BITMAP_OFFSET_INVALID` [7], which effectively disables the use of the I/O bitmap. It then initializes the entire bitmap with a value of 1 (DISALLOW) [8], meaning that all I/O ports are marked as inaccessible. However, since the bitmap base was already set to `IO_BITMAP_OFFSET_INVALID`, these bitmap values are never actually used.

``` c
static inline void tss_setup_io_bitmap(struct tss_struct *tss)
{
    tss->x86_tss.io_bitmap_base = IO_BITMAP_OFFSET_INVALID; // [7]
    // [...]
    memset(tss->io_bitmap.bitmap, 0xff, sizeof(tss->io_bitmap.bitmap)); // [8]
    tss->io_bitmap.mapall[IO_BITMAP_LONGS] = ~0UL;
}

/* Base offset outside of TSS_LIMIT so unpriviledged IO causes #GP */
#define IO_BITMAP_OFFSET_INVALID (__KERNEL_TSS_LIMIT + 1)
```

The I/O bitmap is switched during a context switch. If the previous task was using a bitmap [9], the kernel must invalidate the current TSS bitmap by setting the bitmap base to `IO_BITMAP_OFFSET_INVALID` [10]. If the next task requires an I/O bitmap, the kernel will update it by invoking `tss_update_io_bitmap()` before returning to user space.

``` c
void __switch_to_xtra(struct task_struct *prev_p, struct task_struct *next_p)
{
    unsigned long tifp, tifn;

    // [...]
    tifp = read_task_thread_flags(prev_p);

    switch_to_bitmap(tifp);
    // [...]
}

static inline void switch_to_bitmap(unsigned long tifp)
{
    // [...]
    if (tifp & _TIF_IO_BITMAP) // [9]
        tss_invalidate_io_bitmap();
}

#define tss_invalidate_io_bitmap native_tss_invalidate_io_bitmap

static inline void native_tss_invalidate_io_bitmap(void)
{
    // [...]
    this_cpu_write(cpu_tss_rw.x86_tss.io_bitmap_base, // [10]
               IO_BITMAP_OFFSET_INVALID);
}
```

At this point, you might be wondering: if `sys_iopl(3)` only updates the bitmap base without modifying the bitmap itself — leaving all entries set to 1 (DISALLOW) — how is I/O still possible?

The key lies in the definition of the `IO_BITMAP_OFFSET_VALID_ALL` macro. Instead of pointing to the primary bitmap (`tss->io_bitmap.bitmap`), it actually **points to the secondary bitmap `tss->io_bitmap.mapall`**, which is initialized to all zeros (ALLOW).

``` c
#define IO_BITMAP_OFFSET_VALID_ALL                      \
    (offsetof(struct tss_struct, io_bitmap.mapall) -    \
     offsetof(struct tss_struct, x86_tss))
```

The reason for this design is that the purpose of `iopl(3)` is to **enable access to all I/O ports**. However, the kernel cannot simply set `EFLAGS.IOPL` to 0 directly. Instead, the solution is to introduce an additional bitmap, `mapall`, where all ports are enabled. When `iopl(3)` is executed, the bitmap base is switched to point to this map.

## 3. ioperm

To enable or disable access to a specific range of I/O ports, the `SYS_ioperm` system call is used. This syscall allocates a bitmap object [1], and then, based on the user’s request, either enables [2] or disables [3] access to the corresponding ports.

``` c
long ksys_ioperm(unsigned long from, unsigned long num, int turn_on)
{
    struct io_bitmap *iobm;

    iobm = kmalloc(sizeof(*iobm), GFP_KERNEL); // [1]
    memset(iobm->bitmap, 0xff, sizeof(iobm->bitmap));
    // [...]
    t->io_bitmap = iobm;
    set_thread_flag(TIF_IO_BITMAP);
    
    // [...]
    if (turn_on)
        bitmap_clear(iobm->bitmap, from, num); // [2]
    else
        bitmap_set(iobm->bitmap, from, num); // [3]
    
    // [...]
}
```

In `native_tss_update_io_bitmap()`, the update of the I/O bitmap goes to another if-else branch. Here, the previously allocated bitmap object is copied into the TSS bitmap field (`tss->io_bitmap.bitmap`) [4], and finally, the bitmap base is updated to point to the beginning of that bitmap [5].

``` c
void native_tss_update_io_bitmap(void)
{
	// [...]
    else {
        struct io_bitmap *iobm = t->io_bitmap;

        // [...]
        if (tss->io_bitmap.prev_sequence != iobm->sequence)
            tss_copy_io_bitmap(tss, iobm); // <------------

        // [...]
        *base = IO_BITMAP_OFFSET_VALID_MAP; // [5]
    }
}

static void tss_copy_io_bitmap(struct tss_struct *tss, struct io_bitmap *iobm)
{
    // [...]
    memcpy(tss->io_bitmap.bitmap, iobm->bitmap, // [4]
           max(tss->io_bitmap.prev_max, iobm->max));
    // [...]
}
```

Now, the bitmap being used is the actual `io_bitmap.bitmap`.

``` c
#define IO_BITMAP_OFFSET_VALID_MAP                      \
    (offsetof(struct tss_struct, io_bitmap.bitmap) -    \
     offsetof(struct tss_struct, x86_tss))
```