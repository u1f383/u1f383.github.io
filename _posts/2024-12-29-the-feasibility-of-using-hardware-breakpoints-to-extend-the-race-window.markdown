---
layout: post
title:  "The Feasibility of Using Hardware Breakpoints To Extend the Race Window"
categories: linux
---

There are several ways to extend the time window for race condition vulnerabilities in Linux kernel exploitation, such as FUSE, userfault fd, and timer events. However, in practice, timer events are the most commonly used because FUSE and userfault fd are generally disabled to normal users. But timer events need to be triggered within the race window, and depending on the execution environment, multiple attempts and adjustments may be necessary, which increases the instability of the exploitation. In such a case, having a primitive that behaves similarly to FUSE and userfault fd would provide greater flexibility when exploiting a race condition.

One day, while debugging, I suddenly realized that **hardware breakpoints also share some of these features**: [1] Accessing a specified memory address triggers an exception, allowing for a stable trigger at `copy_from_user()` or `copy_to_user()`; [2] Although a maximum of 4 hardware breakpoints (DR0 to DR3) can be set at a time, if it is possible to wake up or context-switch to the parent process during the exception, the next hardware breakpoint can be updated, achieving a similar effect.

Although I eventually found that it was **not possible** to switch to another process when a trap was triggered, I still wanted to briefly write down the process of my attempts.

## 1. Hardware Breakpoint

A process can insert hardware breakpoints by setting up debug registers (DR). Generally, a parent process configures the DRs of a child process using the ptrace API with the `PTRACE_POKEUSER` command.

The following example code demonstrates this. DR0 to DR3 can be used to specify the addresses to monitor, while DR7 controls the access operations that trigger the trap and other related settings.

``` c
ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[0]), WATCH_ADDRESS);
unsigned long dr7 = 0x3 | (0x3 << 16); // read/write event
ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[7]), dr7);
```

The kernel variable `early_idts[]` defines the handler for the #DB trap as `asm_exc_debug()`, and this IDT entry is initialized during the kernel booting process.

``` c
static const __initconst struct idt_data early_idts[] = {
    INTG(X86_TRAP_DB, asm_exc_debug),
    // [...]
};
```

The function `exc_debug_kernel()` is indirectly invoked by `asm_exc_debug()` [1], and it uses `notify_debug()` [2] to notify other monitoring subsystems that a hardware breakpoint has been triggered.

```
pwndbg> x/10i asm_exc_debug
   0xffffffff82600ce0 <asm_exc_debug>:  nop    DWORD PTR [rax]
   0xffffffff82600ce3 <asm_exc_debug+3>:        cld
   [...]
   0xffffffff82600cf5 <asm_exc_debug+21>:       call   0xffffffff8246abf0 <exc_debug>
```

``` c
DEFINE_IDTENTRY_DEBUG(exc_debug)
{
    exc_debug_kernel(regs, debug_read_clear_dr6()); // [1]
}

static __always_inline void exc_debug_kernel(struct pt_regs *regs,
                         unsigned long dr6)
{
    // [...]
    
    if (notify_debug(regs, &dr6)) // [2]
        goto out;
    
    // [...]
}
```

The function `notify_debug()` internally calls `atomic_notifier_call_chain()` to iterate the variable `&die_chain`, which stores the registered notification callbacks. Finally, the function `notifier_call_chain()` is called [3] to invoke those callback functions.

``` c
static bool notify_debug(struct pt_regs *regs, unsigned long *dr6)
{
    if (notify_die(DIE_DEBUG, "debug", regs, (long)dr6, 0, SIGTRAP) == NOTIFY_STOP)
        return true;
    return false;
}

int notrace notify_die(enum die_val val, const char *str,
           struct pt_regs *regs, long err, int trap, int sig)
{
    struct die_args args = {
        .regs    = regs,
        .str    = str,
        .err    = err,
        .trapnr    = trap,
        .signr    = sig,

    };
    return atomic_notifier_call_chain(&die_chain, val, &args); // <---------
}

int atomic_notifier_call_chain(struct atomic_notifier_head *nh,
                   unsigned long val, void *v)
{
    int ret;

    rcu_read_lock();
    ret = notifier_call_chain(&nh->head, val, v, -1, NULL); // <---------
    rcu_read_unlock();

    return ret;
}

static int notifier_call_chain(struct notifier_block **nl,
                   unsigned long val, void *v,
                   int nr_to_call, int *nr_calls)
{
    struct notifier_block *nb, *next_nb;
    nb = rcu_dereference_raw(*nl);

    while (nb && nr_to_call) {
        next_nb = rcu_dereference_raw(nb->next);
        // [...]
        ret = nb->notifier_call(nb, val, v); // [3]
        nb = next_nb;
        // [...]
    }
    // [...]
}
```

## 2. Notifier Callback

Subsystems can register a notifier function by calling `register_die_notifier()`.

``` c
int register_die_notifier(struct notifier_block *nb)
{
    return atomic_notifier_chain_register(&die_chain, nb);
}
```

By default, there are four notifier callbacks:
- `hw_breakpoint_exceptions_notify()` - Updates the process state and handles perf breakpoint events.
- `kprobe_exceptions_notify()` - A weak definition; for x64, it simply returns.
- `trace_die_panic_handler()` - By default, it just returns.
- `arch_uprobe_exception_notify()` - Handles traps triggered only in userspace.

Among the notifiers, the only one that does something is `hw_breakpoint_exceptions_notify()`. This function further invokes `hw_breakpoint_handler()` to update the perf event, process state, and register values.

``` c
static int hw_breakpoint_handler(struct die_args *args)
{
    // [...]
    for (i = 0; i < HBP_NUM; ++i) {
        // trap which bp
        if (likely(!(dr6 & (DR_TRAP0 << i))))
            continue;

        bp = this_cpu_read(bp_per_reg[i]); // [2]

        // [...]
        // clear register
        (*dr6_p) &= ~(DR_TRAP0 << i);

        // update perf event
        perf_bp_event(bp, args->regs);
    }
}
```

When using `sys_ptrace` to set a hardware breakpoint for a child process, the underlying implementation calls `ptrace_set_breakpoint_addr()` to create a `perf_event` object [1]. As a result, when the #DB handler invokes `perf_bp_event()`, the `bp` parameter refers to the newly created one [2].

``` c
static int ptrace_set_breakpoint_addr(struct task_struct *tsk, int nr,
                                      unsigned long addr)
{
    struct perf_event *bp = t->ptrace_bps[nr];
    // [...]
    if (!bp) {
        bp = ptrace_register_breakpoint(tsk, // [1]
                        X86_BREAKPOINT_LEN_1, X86_BREAKPOINT_WRITE,
                        addr, true);
        // [...]
    }
}
```

The function `perf_bp_event()` doesn't perform any special operations; it simply updates the trap information in the associated `perf_event` object.

``` c
void perf_bp_event(struct perf_event *bp, void *data)
{
    struct perf_sample_data sample;
    struct pt_regs *regs = data;

    perf_sample_data_init(&sample, bp->attr.bp_addr, 0);

    if (!bp->hw.state && !perf_exclude_event(bp, regs))
        perf_swevent_event(bp, 1, &sample, regs);
}
```

In conclusion, when a hardware breakpoint trap is triggered, the #DB handler performs no time-consuming operations, making it **unlikely to extend the race window using this method**.