---
layout: post
title:  "A Quick Note On Two mempolicy Vulnerabilities"
categories: linux
---

## 1. CVE-2022-49080: mm/mempolicy: fix mpol_new leak in shared_policy_replace
> https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4ad099559b00ac01c3726e5c95dc3108ef47d03e

## 1.1. Patch

The patch is very straightforward: initialize the refcount after allocating it.

``` diff
@@ -2733,6 +2733,7 @@ alloc_new:
     mpol_new = kmem_cache_alloc(policy_cache, GFP_KERNEL);
     if (!mpol_new)
         goto err_out;
+    atomic_set(&mpol_new->refcnt, 1);
     goto restart;
 }
```

## 1.2. Root Cause

The system call `SYS_mbind` is used to apply a memory policy to a specified memory range. Internally, it ends up calling the function `do_mbind()` [1].

``` c
SYSCALL_DEFINE6(mbind, unsigned long, start, unsigned long, len,
        unsigned long, mode, const unsigned long __user *, nmask,
        unsigned long, maxnode, unsigned int, flags)
{
    return kernel_mbind(start, len, mode, nmask, maxnode, flags); // <-----------------
}

static long kernel_mbind(unsigned long start, unsigned long len,
             unsigned long mode, const unsigned long __user *nmask,
             unsigned long maxnode, unsigned int flags)
{
    // [...]
    return do_mbind(start, len, lmode, mode_flags, &nodes, flags); // [1]
}
```

Inside `do_mbind()`, a new mempolicy object is created [2], and `mbind_range()` is called to apply the new memory policy to the given region [3].

``` c
static long do_mbind(unsigned long start, unsigned long len,
             unsigned short mode, unsigned short mode_flags,
             nodemask_t *nmask, unsigned long flags)
{
    struct mm_struct *mm = current->mm;
    struct mempolicy *new;

    // [...]
    mmap_write_lock(mm);

    // [...]
    new = mpol_new(mode, mode_flags, nmask); // [2]

    // [...]
    err = mbind_range(mm, start, end, new); // [3]
    
    // [...]
    mmap_write_unlock(mm);
}
```

The memory policy is applied at the VMA level. So, `mbind_range()` iterates through VMAs that overlap the target memory region and uses `vma_replace_policy()` to swap in the new policy [4].

``` c
static int mbind_range(struct mm_struct *mm, unsigned long start,
               unsigned long end, struct mempolicy *new_pol)
{
    // [...]
    for (; vma && vma->vm_start < end; prev = vma, vma = vma->vm_next) {
        vmstart = max(start, vma->vm_start);
        vmend   = min(end, vma->vm_end);

        // [...]
 replace:
        err = vma_replace_policy(vma, new_pol); // [4]
        if (err)
            goto out;
    }
}
```

If the VMA has custom policy ops, `vma_replace_policy()` will invoke the associated `set_policy` handler [5]. It then replace the old policy with duplicated one [6].

``` c
static int vma_replace_policy(struct vm_area_struct *vma,
                        struct mempolicy *pol)
{
    new = mpol_dup(pol);
    
    // [...]
    if (vma->vm_ops && vma->vm_ops->set_policy) {
        err = vma->vm_ops->set_policy(vma, new); // [5]
        // [...]
    }

    old = vma->vm_policy;
    vma->vm_policy = new; // [6]
    mpol_put(old);

    return 0;
}
```

If the memory region is backed by shared memory, the handler `shmem_set_policy()` is triggered [7], which in turn creates a new shared policy node [8] and replaces the existing one using `shared_policy_replace()` [9].

``` c
static const struct vm_operations_struct shmem_vm_ops = {
    // [...]
    .set_policy = shmem_set_policy, // [7]
    // [...]
}

static int shmem_set_policy(struct vm_area_struct *vma, struct mempolicy *mpol)
{
    struct inode *inode = file_inode(vma->vm_file);
    return mpol_set_shared_policy(&SHMEM_I(inode)->policy, vma, mpol);
}

int mpol_set_shared_policy(struct shared_policy *info,
            struct vm_area_struct *vma, struct mempolicy *npol)
{
    int err;
    struct sp_node *new = NULL;
    unsigned long sz = vma_pages(vma);

    if (npol) {
        new = sp_alloc(vma->vm_pgoff, vma->vm_pgoff + sz, npol); // [8]
        // [...]
    }

    err = shared_policy_replace(info, vma->vm_pgoff, vma->vm_pgoff+sz, new); // [9]
    // [...]
    return err;
}
```

If `shared_policy_replace()` finds that the existing shared policy spans the entire new range [10], it tries to allocate a new shared policy node [11] and a new mempolicy object [12].

However, before a fix was applied, **the refcount of this new mempolicy object wasn't being initialized properly [13], which led to a memory leak**.

``` c
static int shared_policy_replace(struct shared_policy *sp, unsigned long start,
                 unsigned long end, struct sp_node *new)
{
    struct sp_node *n_new = NULL;
    struct mempolicy *mpol_new = NULL;
    // [...]
restart:
    write_lock(&sp->lock);
    n = sp_lookup(sp, start, end);
    while (n && n->start < end) {
        // [...]
        if (n->end > end) { // [10]
            if (!n_new)
                goto alloc_new;
            // [...]
        }
    }

alloc_new:
    write_unlock(&sp->lock);
    n_new = kmem_cache_alloc(sn_cache, GFP_KERNEL); // [11]
    mpol_new = kmem_cache_alloc(policy_cache, GFP_KERNEL); // [12]
    // atomic_set(&mpol_new->refcnt, 1); // [13]
    goto restart;
}
```


## 2. CVE-2023-4611: mm/mempolicy: Take VMA lock before replacing policy
> https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6c21e066f9256ea1df6f88768f6ae1080b7cf509

This vulnerability wasn't due to how mempolicy was originally implemented - it emerged as a side effect of adapting to the **new locking mechanism introduced in the mm subsystem**.

### 2.1. Introduction

To avoid race conditions, the kernel requires holding the `mmap_lock` (previously known as `mmap_sem`) when working with VMAs or mm structs. However, when a process has lots of VMAs, accessing just one of them could block all other operations, leading to performance bottlenecks.

To tackle that, Linux [introduced per-VMA locks](https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0b6cc04f3db3604c1485049bc9582523c2b44b75) in April 2023 to allow finer-grained locking within the mm subsystem. This [LWN article](https://lwn.net/Articles/906852/) does a great job explaining the design rationale, challenges, and implementation.

In short, Linux wanted to reduce the performance overhead caused by page faults. Originally, handling a page fault required acquiring the mm read lock, which would block any operation needing the write lock. With the new VMA locks, the page fault handler first attempts to grab the VMA read lock - if that works, it won't block mm write operations. If it fails, it just falls back to using the mm read lock like before.

The mm lock (`mm->mmap_lock`) implementation still works the same way. The only difference is that `mmap_write_unlock()` now also updates a lock sequence number [1] before releasing the lock.

``` c
// ====================== init ======================
static inline void mmap_init_lock(struct mm_struct *mm)
{
    init_rwsem(&mm->mmap_lock);
}

// ====================== read lock ======================
static inline void mmap_read_lock(struct mm_struct *mm)
{
    down_read(&mm->mmap_lock);
}

static inline void mmap_read_unlock(struct mm_struct *mm)
{
    up_read(&mm->mmap_lock);
}

// ====================== write lock ======================
static inline void mmap_write_lock(struct mm_struct *mm)
{
    down_write(&mm->mmap_lock);
}

static inline void mmap_write_unlock(struct mm_struct *mm)
{
    vma_end_write_all(mm); // <-----------------
    up_write(&mm->mmap_lock);
}

static inline void vma_end_write_all(struct mm_struct *mm)
{
    mmap_assert_write_locked(mm);
    WRITE_ONCE(mm->mm_lock_seq, mm->mm_lock_seq + 1); // [1]
}
```

Each VMA allocates its own lock object during initialization via `vma_lock_alloc()` [2].

``` c
static bool vma_lock_alloc(struct vm_area_struct *vma)
{
    vma->vm_lock = kmem_cache_alloc(vma_lock_cachep, GFP_KERNEL);
    init_rwsem(&vma->vm_lock->lock); // [2]
    vma->vm_lock_seq = -1;

    return true;
}
```

A VMA writer is only allowed to acquire the write lock if it's already holding the mm write lock [3]. Once it does, it updates the lock sequence number of VMA [4] under the VMA write lock [5].

``` c
static inline void vma_start_write(struct vm_area_struct *vma)
{
    int mm_lock_seq;

    if (__is_vma_write_locked(vma, &mm_lock_seq)) // <-----------------
        return;

    down_write(&vma->vm_lock->lock); // [5]
    vma->vm_lock_seq = mm_lock_seq; // [4]
    up_write(&vma->vm_lock->lock);
}

static bool __is_vma_write_locked(struct vm_area_struct *vma, int *mm_lock_seq)
{
    mmap_assert_write_locked(vma->vm_mm); // [3]
    *mm_lock_seq = READ_ONCE(vma->vm_mm->mm_lock_seq);
    return (vma->vm_lock_seq == *mm_lock_seq);
}
```

For readers, a VMA read lock only succeeds if the VMA and mm lock sequence numbers don't match. If they match [6, 7], it means a writer is modifying the VMA, and the reader should wait until `mmap_write_unlock()` updates the sequence number, or just fall back to use the mm read lock.

``` c
static inline bool vma_start_read(struct vm_area_struct *vma)
{
    if (vma->vm_lock_seq == READ_ONCE(vma->vm_mm->mm_lock_seq)) // [6]
        return false;

    if (unlikely(down_read_trylock(&vma->vm_lock->lock) == 0))
        return false;

    if (unlikely(vma->vm_lock_seq == READ_ONCE(vma->vm_mm->mm_lock_seq))) { // [7]
        up_read(&vma->vm_lock->lock);
        return false;
    }
    return true;
}

static inline void vma_end_read(struct vm_area_struct *vma)
{
    rcu_read_lock();
    up_read(&vma->vm_lock->lock);
    rcu_read_unlock();
}
```

### 2.2. Root Cause

#### Rebinding a Memory Policy

The `sys_mbind()` syscall internally calls `do_mbind()`, which walks the VMAs and updates their memory policy [1] while holding the mm write lock [2].

``` c
static long do_mbind(unsigned long start, unsigned long len,
             unsigned short mode, unsigned short mode_flags,
             nodemask_t *nmask, unsigned long flags)
{
    new = mpol_new(mode, mode_flags, nmask);
    
    // [..]
    mmap_write_lock(mm); // [2]
    
    vma_iter_init(&vmi, mm, start);
    prev = vma_prev(&vmi);
    for_each_vma_range(vmi, vma, end) {
        err = mbind_range(&vmi, vma, &prev, start, end, new); // [1]
    }
    
    mmap_write_unlock(mm);
    // [..]
}
```

Replacing the mempolicy involves decreasing the refcount of the old object [3]. Once the refcount reaches zero, the old mempolicy object gets freed.

``` c
static int vma_replace_policy(struct vm_area_struct *vma,
                        struct mempolicy *pol)
{
    // [...]
    new = mpol_dup(pol);
    
    // [...]
    old = vma->vm_policy;
    vma->vm_policy = new;
    mpol_put(old); // [3]

    return 0;
}
```

#### Page Faults

Before the per-VMA locks were added, page faults were handled while holding the mm read lock [1].

``` c
static inline
void do_user_addr_fault(struct pt_regs *regs,
            unsigned long error_code,
            unsigned long address)
{
    // [...]
    
    mmap_read_trylock(mm); // [1]
    vma = find_vma(mm, address);
    fault = handle_mm_fault(vma, address, flags, regs);
    mmap_read_unlock(mm);
    
    // [...]
}
```

Now, **in the newer implementation**, it first tries to use the VMA read lock [2]. If that fails, it falls back to using the mm read lock [3].

``` c
static inline
void do_user_addr_fault(struct pt_regs *regs,
            unsigned long error_code,
            unsigned long address)
{
    // [...]
    vma = lock_vma_under_rcu(mm, address); // [2]
    fault = handle_mm_fault(vma, address, flags | FAULT_FLAG_VMA_LOCK, regs);
    vma_end_read(vma);
    // [...]

lock_mmap:
    vma = lock_mm_and_find_vma(mm, address, regs); // [3]
    fault = handle_mm_fault(vma, address, flags, regs);
    mmap_read_unlock(mm);
    // [...]
}
```


When dealing with anonymous memory [4], `handle_mm_fault()` eventually calls `vma_alloc_folio()` [5] to allocate a page.

``` c
vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
               unsigned int flags, struct pt_regs *regs)
{
    // [...]
    else
        ret = __handle_mm_fault(vma, address, flags); // <-----------------
    // [...]
}

static vm_fault_t __handle_mm_fault(struct vm_area_struct *vma,
        unsigned long address, unsigned int flags)
{
    struct vm_fault vmf = {
        .vma = vma,
        .address = address & PAGE_MASK,
        .real_address = address,
        .flags = flags,
        .pgoff = linear_page_index(vma, address),
        .gfp_mask = __get_fault_gfp_mask(vma),
    };
    
    // [...]
    return handle_pte_fault(&vmf); // <-----------------
}

static vm_fault_t handle_pte_fault(struct vm_fault *vmf)
{
    // [...]
    if (!vmf->pte)
        return do_pte_missing(vmf); // <-----------------
    // [...]
}

static vm_fault_t do_pte_missing(struct vm_fault *vmf)
{
    if (vma_is_anonymous(vmf->vma)) // [4]
        return do_anonymous_page(vmf); // <-----------------
    // [...]
}

static vm_fault_t do_anonymous_page(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    
    // [...]
    folio = vma_alloc_zeroed_movable_folio(vma, vmf->address); // <-----------------
    entry = mk_pte(&folio->page, vma->vm_page_prot);
    vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
            &vmf->ptl);
    set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);
    // [...]
}

#define vma_alloc_zeroed_movable_folio(vma, vaddr) \
    vma_alloc_folio(GFP_HIGHUSER_MOVABLE | __GFP_ZERO, 0, vma, vaddr, false) // [5]
```

`vma_alloc_folio()` gets the mempolicy [6], uses it to allocate the page, and then releases it [7].

``` c
struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
        unsigned long addr, bool hugepage)
{
    struct mempolicy *pol;
    int node = numa_node_id();
    struct folio *folio;
    int preferred_nid;
    nodemask_t *nmask;

    pol = get_vma_policy(vma, addr); // [6]
    if (pol->mode == MPOL_INTERLEAVE) {
        // [...]
        goto out;
    }
    if (pol->mode == MPOL_PREFERRED_MANY) {
        // [...]
        goto out;
    }

    // [...]
    mpol_cond_put(pol); // [7], dec refcount if pol->flags & MPOL_F_SHARED
out:
    return folio;
}
```

And `__get_vma_policy()` is where it grabs `vma->vm_policy` and increases the refcount [8].

``` c
static struct mempolicy *get_vma_policy(struct vm_area_struct *vma,
                        unsigned long addr)
{
    struct mempolicy *pol = __get_vma_policy(vma, addr); // <-----------------
    // [...]
    return pol;
}

struct mempolicy *__get_vma_policy(struct vm_area_struct *vma,
                        unsigned long addr)
{
    if (vma) {
        // [...]
        else if (vma->vm_policy) {
            pol = vma->vm_policy; // [8]
            if (mpol_needs_cond_ref(pol))
                mpol_get(pol); // inc refcount if pol->flags & MPOL_F_SHARED
        }
    }

    return pol;
}
```

#### The Race Condition

Here's the problem: `sys_mbind()` updates the mempolicy **using the mm write lock**, but page faults only **hold the VMA read lock**. That opens up a race window.

A simplified timeline of how the UAF happens is as follows:

```
[Thread-1]                          [Thread-2]
sys_mbind
  do_mbind
    hold mm write lock
    vma_replace_policy
       old = vma->vm_policy
                                    do_user_addr_fault
                                      hold VMA read lock
                                      __get_vma_policy
                                        pol = vma->vm_policy
       vma->vm_policy = new
       mpol_put(old)
         -> dec refcount
         -> free old
                                        mpol_get(pol)
                                          -> inc refcount
                                          -> UAF write
                                      release VMA read lock
    release mm write lock
```

### 2.3. Patch

To fix these issues, just make sure we properly acquire the VMA write lock when we're modifying a VMA's mempolicy.

For example, `mpol_rebind_mm()` now calls `vma_start_write()` before changing the policy.

``` diff
@@ -384,8 +384,10 @@ void mpol_rebind_mm(struct mm_struct *mm, nodemask_t *new)
     VMA_ITERATOR(vmi, mm, 0);
 
     mmap_write_lock(mm);
-    for_each_vma(vmi, vma)
+    for_each_vma(vmi, vma) {
+        vma_start_write(vma);
         mpol_rebind_policy(vma->vm_policy, new);
+    }
```