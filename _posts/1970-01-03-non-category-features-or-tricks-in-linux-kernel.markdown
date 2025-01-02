---
layout: post
title:  "Non-category Features or Tricks in Linux Kernel"
categories: cheatsheet
---

## Deferred tasks

The function `task_work_add()` is used to add tasks into workqueue. Before irq or syscall handlers return, the function `exit_to_user_mode_prepare()` is called to handle these tasks.
``` c
static void exit_to_user_mode_prepare(struct pt_regs *regs)
{
    unsigned long ti_work;

    ti_work = read_thread_flags();
    if (unlikely(ti_work & EXIT_TO_USER_MODE_WORK))
        ti_work = exit_to_user_mode_loop(regs, ti_work); // <---------
    // [...]
}

static unsigned long exit_to_user_mode_loop(struct pt_regs *regs,
                        unsigned long ti_work)
{
    while (ti_work & EXIT_TO_USER_MODE_WORK) {
        // [...]
        
        if (ti_work & _TIF_NOTIFY_RESUME)
            resume_user_mode_work(regs); // <---------
        
        // [...]
    }
}

static inline void resume_user_mode_work(struct pt_regs *regs)
{
    // [...]
    if (unlikely(task_work_pending(current)))
        task_work_run(); // <---------
}

void task_work_run(void)
{
    struct task_struct *task = current;
    struct callback_head *work, *head, *next;
    
    for (;;) {
        work = READ_ONCE(task->task_works);
        // [...]
        
        if (!work)
            break;
        
        // [...]
        do {
            next = work->next;
            work->func(work);
            work = next;
            // [...]
        } while (work);
    }
}

```
