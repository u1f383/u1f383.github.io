---
layout: post
title:  "Uncategorized Features or Tricks in Linux Kernel"
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

## Socket

### Ownership

```
=> lock_sock()
==> sk->sk_lock.owned = 1;

=> ...

=> release_sock()
==> sock_release_ownership()
===> sk->sk_lock.owned = 0;
```

### SKB API

``` c
// Copy data from skb to kernel buffer
int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len);

// Duplicate an sk_buff. Both skbs share the same packet data but not structure. It won't update the refcount of data pages
struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask);

// Free an sk_buff
// ==> kfree_skb() ==> kfree_skb_reason()
static inline void consume_skb(struct sk_buff *skb);

// Allocate skb with page frags
struct sk_buff *alloc_skb_with_frags(unsigned long header_len, unsigned long data_len, int order, /* ... */);

// Allocate a network buffer with header size
static inline struct sk_buff *alloc_skb(unsigned int size, /* ... */)

// Copy old skb header to new skb header
void skb_copy_header(struct sk_buff *new, const struct sk_buff *old);

// Get skb shared info
#define skb_shinfo(SKB)    ((struct skb_shared_info *)(skb_end_pointer(SKB)))
static inline unsigned char *skb_end_pointer(const struct sk_buff *skb)
{
    return skb->head + skb->end;
}

// Empty a list. Each buffer is removed from the list and one reference dropped
// ==> foreach skb in list, kfree_skb_reason(skb)
static inline void __skb_queue_purge(struct sk_buff_head *list);
```

## Linked List

Get entry
- `list_empty()` + `list_first_entry()`
- `list_first_entry_or_null()`