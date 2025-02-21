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

## RWSEM

- Read Lock: `down_read()`
    - Acquires the semaphore for reading.
- Write Lock: `down_write()`
    - Acquires the semaphore for writing.
- Unlocking: `up_read()` and `up_write()` release the semaphore after the operation is complete.

## Socket

### Field

- `sk_forward_alloc` - Space allocated forward (pre-allocation)
    - `sk_wmem_schedule()` - Checks whether there is enough sndbuf; if not, it calls `sk_forward_alloc_add()` to allocate more.
- `sk_wmem_queued` - Persistent queue size
    - `sk_wmem_queued_add()`

### Ownership

When a socket is locked, it essentially sets the `owned` member inside a spinlock.

```
=> lock_sock()
==> spin_lock_bh(&sk->sk_lock.slock)
==> sk->sk_lock.owned = 1
==> spin_unlock_bh(&sk->sk_lock.slock)

=> ...

=> release_sock()
==> spin_lock_bh(&sk->sk_lock.slock)
==> sock_release_ownership()
===> sk->sk_lock.owned = 0;
==> spin_unlock_bh(&sk->sk_lock.slock)
```

This also means that when user space invokes a syscall to acquire the socket's ownership, it checks the owned status.

``` c
static inline bool sock_owned_by_user(const struct sock *sk)
{
    // [...]
    return sk->sk_lock.owned;
}
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

// Copy a datagram to an iovec iterator
int skb_copy_datagram_iter(const struct sk_buff *skb, int offset, struct iov_iter *to, int len)
```

### scatterlist

A **scatterlist** is a data structure used to describe a **list of memory segments** that may be physically scattered in memory but are logically contiguous for I/O operations.

``` c
struct scatterlist {
	unsigned long	page_link;
	unsigned int	offset;
	unsigned int	length;
    // [...]
};
```

`sk_msg` uses a **scatterlist** to track the position and size of in/out buffers:

- `sk_msg_init()` - Initializes a given number of entries, setting them to zero and marking the last entry as the end.
    - The struct `sk_msg` by default contains `MAX_MSG_FRAGS` + 2 (19) struct scatterlist entries (`msg->sg.data[]`).
- `sk_msg_alloc()` - Allocates a new scatterlist entry.
- `sk_msg_trim()` - Trims excess allocated space; internally, it handles scatterlist updates.
    - This function should be called to roll back `sk_msg` state in case of transmission failure.
- `sk_msg_free()` - Iterates through scatterlist entries and calls `sk_msg_free_elem()` to release `page_link` (`put_page()`).
- `sk_msg_clone()` - Allows two `sk_msg` instances to share the same `page_link`; internally, it updates the page refcount.
- `sk_msg_page_add()` - Adds a new page object as a scatterlist entry.
- `sk_msg_full()` - Checks whether `sk_msg` is full, meaning the difference between start and end equals `MAX_MSG_FRAGS`.
- `sk_msg_zerocopy_from_iter()` - Directly assigns `sk_msg` to use the iov_iter page object.
- `sk_msg_memcopy_from_iter()` - Copies data from iov_iter into `sk_msg`.

Lower-Level APIs

- `sg_init_table()` - Initializes the number of entries.
- `sg_set_buf()` - Sets the address and size for the Nth entry. Internally, it converts the buffer address into a page address.
- `sg_set_page()` - Sets the page for the Nth entry, requiring a size and offset.
    - Important! This does not increase the page reference count, so `get_page()` must be called manually.
- `sg_mark_end()` / `sg_unmark_end()` - Marks or unmarks the end of a scatterlist entry.
    - Sets page_link with `SG_END` (0x2).
- `sg_chain()` - Links two scatterlist instances together.
    - Sets page_link with `SG_CHAIN` (0x1).
- `sg_next()` - Retrieves the next scatterlist entry.


Common Execution Flow

``` c
// [1] allocate new one with provided length
sk_msg_alloc(sk, msg_pl, len, 0);

// [2] copy data from iterator and update length
ret = sk_msg_zerocopy_from_iter(sk, &msg->msg_iter, msg_pl, try_to_copy);

// [3] set the which sg element is first one (index)
sk_msg_sg_copy_set(msg_pl, first);

// ... do somthing and error occurs

// [4] rollback index
sk_msg_sg_copy_clear(msg_pl, first);

// [5] rollback iterateor
iov_iter_revert(&msg->msg_iter, msg_pl->sg.size - orig_size);

// [6] rollback sk_msg
sk_msg_trim(sk, msg_pl, orig_size);
```

### Others

When a socket detects that the send buffer is full, it waits until enough memory becomes available before retrying transmission. During this process, **the socket lock is released**, which could lead to potential issues that should be monitored.
Additionally, for receive-related operations, when waiting for incoming data, `release_sock()` is typically called to prevent blocking other operations.

```
=> sk_stream_memory_free() - Checks if there is enough memory available
==> if (sk->sk_wmem_queued >= sk->sk_sndbuf) return false
=> sk_stream_wait_memory()
==> Set bit `SOCK_NOSPACE`
==> sk_wait_event() - Waits to be woken up
===> release_sock() <------------- Releases the socket lock
===> wait_woken()
===> lock_sock()
```

## Linked List

Retrieving an Entry from a List
- `list_empty()` + `list_first_entry()`
    - Since `list_first_entry()` returns the head address when no entry exists, it is necessary to **check with `list_empty()`** first to avoid errors.
- `list_first_entry_or_null()`
    - This function directly returns NULL if the list is empty, eliminating the need for an explicit `list_empty()` check.

## IO Iteration

`iov_iter_revert()`
- When functions like `iov_iter_get_pages2()` or `iov_iter_extract_pages()` are called to retrieve pages from an I/O vector, a failure during execution may require restoring the original iterator state.
- This function is used to restore the original iov_len by reverting the changes made during iteration.

## Bit and Reference Count Operations

- `test_and_set_bit()` – Sets a bit and returns its previous value.
- `test_and_clear_bit()` – Clears a bit and returns its previous value.
- `refcount_dec_and_test()` – Decrements the refcount and **returns true if the result is 0**, otherwise false.
- `atomic_inc_not_zero()` – Increments the refcount only if it is nonzero; returns true **if successful (nonzero)**, false otherwise.

## Delayed Work Handling

- `schedule_delayed_work()` – Queues a delayed work item, which will be scheduled and executed after the specified delay.
- `cancel_delayed_work()` – Cancels the delayed work if it has not started; if already running, it does not wait for it to finish.
- `cancel_delayed_work_sync()` – Cancels the delayed work and **waits for** it to finish before continuing execution.

## Splice EOF Handling

```
do_splice_direct()
=> splice_direct_to_actor()
==> do_splice_eof(sd)
===> direct_file_splice_eof(sd->file)
====> sock_splice_eof(struct socket, file->private_data) // proto_ops
=====> inet_splice_eof(struct sock, socket->sk)          // protocol
```

## Poll Execution Flow

```
vfs_poll() -> file->f_op->poll
=> sock_poll() (file_operations socket_file_ops poll)
==> tcp_poll() (proto_ops inet_stream_ops poll)
```

## kfree_rcu

When releasing an object using the `kfree_rcu()` API, there is a mandatory five-second delay (`KFREE_DRAIN_JIFFIES`) before the object is guaranteed to be freed.

``` c
/*
 * This function is invoked after the KFREE_DRAIN_JIFFIES timeout.
 */
static void kfree_rcu_monitor(struct work_struct *work) {...}
```

## Thread

`CLONE_THREAD`
- share cred object (`struct cred`) in `copy_creds()`