---
layout: post
title:  "diceCTF 2026 - corkelslop"
categories: Linux
---

This week I played diceCTF 2026 with team **fewer** and spent 12 hours solving a Linux kernel challenge, **corkelslop**. This post is a simple writeup without too much detail, and you can find the full exploit [here](/assets/dicectf-2026-corkelslop-exp.c).

## 1. Bug

There is a **race condition** between `delete_entry()` and `check_entry()`.

`check_entry()` [1] calls `xa_load()` to retrieve the entry without a spinlock or RCU lock, so it is possible that **the entry has been deleted** by `delete_entry()` in the meantime. Later, `destruct_entry()` [2] is called on the released object to **free it a second time**.

``` c
static int check_entry(struct cornelslop_user_entry *ue)
{
    uint8_t shash[SHA256_DIGEST_SIZE];
    struct cornelslop_entry *e;
    int ret = 0;

    e = xa_load(&cornelslop_xa, ue->id); // [1]
    // [...]
    
    ret = sha256_va_range(e->va_start, e->va_end, shash);
    ue->corrupted = memcmp(e->shash, shash, SHA256_DIGEST_SIZE);

    if (ue->corrupted) {
        xa_erase(&cornelslop_xa, ue->id);
        destruct_entry(e); // [2]
        // [...]
    }

finish:
    return ret;
}
```

The flow to trigger UAF and double free is as follows:

```
[Thread-1]                               [Thread-2]
delete_entry()                           check_entry()
                                          e = xa_load(&cornelslop_xa, ue->id)
                                          sha256_va_range(e->va_start, e->va_end, shash)
                                           ...
 e = xa_erase(&cornelslop_xa, ue->id)
 destruct_entry(e)
  call_rcu(&e->rcu, destruct_entry_rcu)

[=== RCU ===]                             [=== context switch ===]
destruct_entry_rcu()
 kfree(e)
                                          access e <--- UAF
                                          destruct_entry(e) <--- double free
```

## 2. Problems

### 2.1. Race window & RCU

But the problem is that the RCU callback requires **some time (RCU period)** and a **context switch once on each CPUs** to be triggered, so `sha256_va_range()` has to run for a long time.

I used the **shared memory trick** to extend race window, and you can read [Faith's post](https://faith2dxy.xyz/2025-11-28/extending_race_window_fallocate/) for more details. The only difference is that the environment has no ramfs mountpoint, so I used `memfd_create` instead.

Internally, the shared memory page fault handler calls `shmem_falloc_wait()` to wait for hole punching, and it then calls `schedule()` [1] to perform a context switch, which also satisfies one of the conditions to trigger RCU callback.

``` c
static vm_fault_t shmem_falloc_wait(struct vm_fault *vmf, struct inode *inode)
{
    // [...]
    if (shmem_falloc &&
        shmem_falloc->waitq &&
        vmf->pgoff >= shmem_falloc->start &&
        vmf->pgoff < shmem_falloc->next) {
        // [...]
        prepare_to_wait(shmem_falloc_waitq, &shmem_fault_wait,
                TASK_UNINTERRUPTIBLE);
        spin_unlock(&inode->i_lock);
        schedule(); // [1]
        // [...]
    }
    // [...]
}
```

### 2.2. Cross the cache

Even with a double free primitive, we can do nothing because entries are allocated from the specific cache `cornelslop_entry_cachep`. So the only way to exploit it is to **perform a cross-cache attack**.

We first allocate another entry to **reclaim the freed object**, and once the RCU callback is triggered, the object is released again. It allows us to **hold a reference from the xarray to the UAF object**.

To achieve the cross-cache attack, we have to spray lots of entries at the beginning, but due to `alloc_id()` range, we can only allocate entries up to `MAX_ENTRIES` (128), and it is totally insufficient.

Unlike [kqx's solution](https://kqx.io/writeups/cornelslop/#the-multicore-trick), which leveraged the object releasing mechanism in a multicore environment, I chose a relatively stupid and brute-force way to spray entries.

We found that there is a `sha256_va_range()` [1] call between the entry allocation and `alloc_id()`. In theory, we can spawn thousands of threads and use the shared memory trick again to extend the race window. Each one allocates an entry and all of them are released after some time [2]. This allows us to allocate more than `MAX_ENTRIES` entries!

``` c
static int add_entry(struct cornelslop_user_entry *ue)
{
    struct cornelslop_entry *e, *old;
    int ret = 0;
    int id;

    if (ue->va_end < ue->va_start)
        return -EINVAL;

    e = kmem_cache_alloc(cornelslop_entry_cachep, GFP_KERNEL | __GFP_ZERO);
    // [...]
    ret = sha256_va_range(e->va_start, e->va_end, e->shash); // [1]
    // [...]
    id = alloc_id();
    if (id < 0) {
        ret = id;
        goto fail;
    }
    // [...]
fail:
    kfree(e); // [2]
    return ret;
}
```

But in fact, the number of entries is still not enough. The reason is that after the hole punch finishes, the CPU will not schedule automatically, and other threads are unable to be scheduled to call `add_entry()`.

How to solve it? One solution is to **punch the hole again and again**, and it works perfectly 🤣!

``` c
while (!stop) {
    usleep(50);
    SYSCHK(fallocate(memfd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, MAX_LEN));
}
```

However, we cannot accurately control the order in which threads call `kfree(e)`, which makes it quite unstable.

Anyway, it works 😉.

### 2.3. Page UAF

After we return the slab containing the UAF object back to the buddy system, we allocate lots of **pipe pages** to reclaim it.

Remember we still have a reference to the UAF object? We then call `delete_entry()` on that entry, and `kfree()` is applied on one of the pipe pages. So now we have a **page UAF**!

The remaining steps are fairly straightforward: spraying page tables, reading the empty zero page PTE, calculating the core pattern PTE, hijacking the page table, overwriting the core pattern, and finally triggering a segfault to read the flag.