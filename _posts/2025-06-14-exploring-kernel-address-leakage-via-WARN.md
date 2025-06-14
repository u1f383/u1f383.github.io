---
layout: post
title:  "Exploring Kernel Address Leakage via WARN()"
categories: linux
---

In the kernelCTF environment, people tend to leak kernel addresses via hardware side channels. I started to wonder if there were alternative methods to leak the kernel base. During my exploration, I discovered that triggering the `WARN()` function can produce error messages that include multiple memory addresses — potentially revealing both kernel text and heap addresses.

Unfortunately, I haven't yet found a stable execution path that reliably triggers a `WARN()` call, so I'm documenting my findings here for future reference.

## How WARN() Works

The `WARN()` macro expands to a function call to `__warn_printk()` [1] followed by the `ud2` [2] instruction.

``` c
#define WARN(condition, format...) ({                \
    int __ret_warn_on = !!(condition);               \
    if (unlikely(__ret_warn_on))                     \
        __WARN_printf(TAINT_WARN, format); /*[1] */  \
    unlikely(__ret_warn_on);                         \
})

#define __WARN_printf(taint, arg...) do {                     \
    __warn_printk(arg);                                       \
    __WARN_FLAGS(BUGFLAG_NO_CUT_HERE | BUGFLAG_TAINT(taint)); \
} while (0)

#define __WARN_FLAGS(flags)                                    \
do {                                                           \
    __auto_type __flags = BUGFLAG_WARNING|(flags);             \
    _BUG_FLAGS(ASM_UD2, __flags, ASM_REACHABLE);  /* [2] */    \
} while (0)

#define ASM_UD2  ".byte 0x0f, 0x0b"
#define _BUG_FLAGS(ins, flags, extra)                           \
do {                                                            \
    asm_inline volatile("1:\t" ins "\n"                         \
        ".pushsection __bug_table,\"aw\"\n"                     \
        "2:\t" __BUG_REL(1b) "\t# bug_entry::bug_addr\n"        \
        "\t"  __BUG_REL(%c0) "\t# bug_entry::file\n"            \
        "\t.word %c1"        "\t# bug_entry::line\n"            \
        "\t.word %c2"        "\t# bug_entry::flags\n"           \
        "\t.org 2b+%c3\n"                                       \
        ".popsection\n"                                         \
        extra                                                   \
        : : "i" (__FILE__), "i" (__LINE__),                     \
        "i" (flags),                                            \
        "i" (sizeof(struct bug_entry)));                        \
} while (0)
```

However, `__warn_printk()` itself doesn't emit a detailed message; the actual output happens when `ud2` triggers a trap handled by the `exc_invalid_op` exception handler.

``` c
void __warn_printk(const char *fmt, ...)
{
    bool rcu = warn_rcu_enter();
    va_list args;

    pr_warn(CUT_HERE);

    va_start(args, fmt);
    vprintk(fmt, args);
    va_end(args);
    warn_rcu_exit(rcu);
}
```

The `ud2` instruction causes a trap that is handled by `exc_invalid_op`, which internally calls `__report_bug()` [3].

``` c
DEFINE_IDTENTRY_RAW(exc_invalid_op)
{
    irqentry_state_t state;
    // [..]
    handle_bug(regs); // <-------------
}

static noinstr bool handle_bug(struct pt_regs *regs)
{
    bool handled = false;
    int ud_type;
    u32 imm;

    // [...]
    report_bug(regs->ip, regs); // [3]
}
```

During compilation, the macros related to bug handling are stored in the `__start___bug_table`. The `__report_bug()` function finds the corresponding bug entry using the instruction pointer [4] and extracts metadata such as whether it's a `BUG`, `WARNING`, or a one-time check (`ONCE`).

``` c
static enum bug_trap_type __report_bug(unsigned long bugaddr, struct pt_regs *regs)
{
    struct bug_entry *bug;
    const char *file;
    unsigned line, warning, once, done;

    if (!is_valid_bugaddr(bugaddr))
        return BUG_TRAP_TYPE_NONE;

    bug = find_bug(bugaddr);
    warning = (bug->flags & BUGFLAG_WARNING) != 0;
    once = (bug->flags & BUGFLAG_ONCE) != 0;
    done = (bug->flags & BUGFLAG_DONE) != 0;

    if (warning && once) {
        if (done)
            return BUG_TRAP_TYPE_WARN;
            
        bug->flags |= BUGFLAG_DONE;
    }

    if (warning) {
        __warn(file, line, (void *)bugaddr, BUG_GET_TAINT(bug), regs,
               NULL);
        return BUG_TRAP_TYPE_WARN;
    }
    // [...]
}

struct bug_entry *find_bug(unsigned long bugaddr)
{
    struct bug_entry *bug;

    for (bug = __start___bug_table; bug < __stop___bug_table; ++bug)
        if (bugaddr == bug_addr(bug)) // [4]
            return bug;
    // [...]
}
```

The `__warn()` function prints register values via `show_regs()`. If the trap is triggered from user space, it only dumps user registers; otherwise, all registers are dumped.

``` c
void __warn(const char *file, int line, void *caller, unsigned taint,
        struct pt_regs *regs, struct warn_args *args)
{
    // [...]
    if (regs)
        show_regs(regs);
    // [...]
}

void show_regs(struct pt_regs *regs)
{
    enum show_regs_mode print_kernel_regs;

    // [...]
    print_kernel_regs = user_mode(regs) ? SHOW_REGS_USER : SHOW_REGS_ALL;
    __show_regs(regs, print_kernel_regs, KERN_DEFAULT);
    // [...]
}
```

## How the Leak Happens

These registers dumped by the kernel are valuable:
1. The GS base register points to a heap address because it holds the per-CPU data region.
2. Other registers may retain kernel text pointers.

```
...
[   29.754688] RSP: 0018:ffffc900006cbb68 EFLAGS: 00000202
[   29.754875] RAX: 00000000000000db RBX: ffffc900006cbf58 RCX: 0000000000000000
[   29.755056] RDX: ffffffffffffffff RSI: 00000000000000db RDI: ffffc900006cbf58
[   29.755348] RBP: ffffc900006cbf48 R08: 0000000000000000 R09: 0000000000000000
[   29.755545] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[   29.755775] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   29.756070] FS:  000000000d64b380(0000) GS:ffff88811c500000(0000) knlGS:0000000000000000
[   29.756380] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   29.756668] CR2: 000000000049e380 CR3: 0000000104cb0000 CR4: 00000000000006e0
...
```

As a result, if we can reliably trigger a call to `WARN()`, `WARN_ON()`, `WARN_ON_ONCE()` or `__warn()` from user space, we may be able to establish a stable kernel address leak primitive without relying on hardware side channels.
