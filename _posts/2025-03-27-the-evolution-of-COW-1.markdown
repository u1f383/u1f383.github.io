---
layout: post
title:  "The Evolution of Dirty COW (1)"
categories: linux
---

The Linux kernel has memory management (mm) related bugs over the years. One of the most well-known is the **Dirty COW**. Since then, researchers have found similar bugs rooted in the same issue, popping up in areas like **huge pages** and **shared memory**.

Even though the mm subsystem has gone through a lot of changes and improvements over time, revisiting these classic bugs is still very useful. 

In this post, I'll walk through the root cause of **Dirty COW** and share my thought process while digging into it. In the next posts, I'll further take a closer look at two related bugs: **Huge Page Dirty COW** and **Shared Memory Dirty COW**.

> Reference: 
> 1. https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619
> 2. https://spectralops.io/blog/what-is-the-dirty-cow-exploit-and-how-to-prevent-it/
> 3. https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails

## 1. Overview

Here's a rough breakdown of how the **Dirty COW (CVE-2016-5195)** vulnerability gets triggered:
1. When accessing memory via `/proc/self/mem`, the fault comes with the `FOLL_FORCE` flag. This flag basically tells the kernel to ignore read/write permissions.
2. Loading a page can be divided into three steps:
    - [1] Load the PTE,
    - [2] Check if COW is needed,
    - [3] Get the actual page.
3. To bypass write protection on the COW mapping of a read-only file, the kernel clears the `FOLL_WRITE` flag - the one used to check PTE write permissions.
4. Now, between clearing `FOLL_WRITE` and getting the page, if the PTE is zeroed out in the same time, the kernel will retry the whole sequence. But on retry, `FOLL_WRITE` is already cleared.
5. Without `FOLL_WRITE`, when the kernel loads the PTE again, it just maps directly to the file content - even though the memory operation is actually a write.
6. As a result, the write goes straight into the file, even if it was originally mapped with read-only permissions.

## 2. Memory Management
### 2.1. Accessing /proc/self/mem

When trying to write to `/proc/self/mem`, the kernel handles it through the `mem_write()` function [1], which then calls into `mem_rw()` [2].

``` c
static const struct pid_entry tgid_base_stuff[] = {
    // [...]
    REG("mem", S_IRUSR|S_IWUSR, proc_mem_operations),
    // [...]
};

static const struct file_operations proc_mem_operations = {
    // [...]
    .write = mem_write, // [1]
    // [...]
};

static ssize_t mem_write(struct file *file, const char __user *buf,
             size_t count, loff_t *ppos)
{
    return mem_rw(file, (char __user*)buf, count, ppos, 1 /* write */);
}
```

Inside `mem_rw()`, the key thing is that it **sets the flag `FOLL_FORCE`** [2]. This tells the kernel: "let me access this memory regardless of regular permissions." This flag is commonly used when accessing memory via ptrace or `/proc/self/mem`.

Since the memory might belong to another process, the kernel uses `access_remote_vm()` [3] to handle it.

``` c
static ssize_t mem_rw(struct file *file, char __user *buf,
            size_t count, loff_t *ppos, int write)
{
    struct mm_struct *mm = file->private_data;
    // [...]
    flags = FOLL_FORCE | (write ? FOLL_WRITE : 0); // [2]
    
    while (count > 0) {
        size_t this_len = min_t(size_t, count, PAGE_SIZE);
        this_len = access_remote_vm(mm, addr, page, this_len, flags); // [3]
        // [...]
    }
    // [...]
}
```

The actual work of getting the page happens in `get_user_pages_remote()` [4], which eventually calls into `__get_user_pages()` [5].

It is important to note that the function `get_user_pages_remote()` is invoked while a read lock on `mm` is held [6]. Since a read lock can be acquired multiple times, this may introduce potential race conditions.

``` c
int access_remote_vm(struct mm_struct *mm, unsigned long addr,
        void *buf, int len, unsigned int gup_flags)
{
    return __access_remote_vm(mm, addr, buf, len, gup_flags); // <-----------------
}

int __access_remote_vm(struct mm_struct *mm, unsigned long addr, void *buf,
               int len, unsigned int gup_flags)
{
    // [...]
    down_read(&mm->mmap_sem); // [6]

    // [...]
    while (len) {
        // [...]
        ret = get_user_pages_remote(tsk, mm, addr, 1 /* write */, // [4]
                write, 1 /* force */, &page, &vma);
        // [...]
    }
    
    // [...]
    up_read(&mm->mmap_sem);
}

long get_user_pages_remote(struct task_struct *tsk, struct mm_struct *mm,
        unsigned long start, unsigned long nr_pages,
        int write, int force, struct page **pages,
        struct vm_area_struct **vmas)
{
    return __get_user_pages_locked(tsk, mm, start, nr_pages, write, force, // <-----------------
                       pages, vmas, NULL, false,
                       FOLL_TOUCH | FOLL_REMOTE);
}

static __always_inline long __get_user_pages_locked(struct task_struct *tsk,
                        struct mm_struct *mm,
                        unsigned long start,
                        unsigned long nr_pages,
                        int write, int force,
                        struct page **pages,
                        struct vm_area_struct **vmas,
                        int *locked, bool notify_drop,
                        unsigned int flags)
{
    // [...]
    if (pages)
        flags |= FOLL_GET;
    if (write)
        flags |= FOLL_WRITE; // set
    if (force)
        flags |= FOLL_FORCE; // set
    // [...]
    for (;;) {
        ret = __get_user_pages(tsk, mm, start, nr_pages, flags, pages, // [5]
                       vmas, locked);
        // [...]
    }
    // [...]
}
```

Within `__get_user_pages()`, the kernel first finds the corresponding VMA [7], then checks if the requested access is allowed using `check_vma_flags()` [8]. Now here's the trick: if you're trying to write to a memory region that doesn't have write permission (`VM_WRITE`), the access would normally fail. But if you're using `FOLL_FORCE` and the region is marked COW, the access is allowed [9, 10].

``` c
long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
        unsigned long start, unsigned long nr_pages,
        unsigned int gup_flags, struct page **pages,
        struct vm_area_struct **vmas, int *nonblocking)
{
    // [...]
    do {
        unsigned int foll_flags = gup_flags;
        
        // [...]
        
        if (!vma || start >= vma->vm_end) {
            vma = find_extend_vma(mm, start); // [7], find the corresponding VMA
            // [...]
            if (!vma || check_vma_flags(vma, gup_flags)) // [8]
                return i ? : -EFAULT;
            // [...]
        }
retry:
        // [...]
        page = follow_page_mask(vma, start, foll_flags, &page_mask);
        if (!page) {
            int ret;
            ret = faultin_page(tsk, vma, start, &foll_flags,
                    nonblocking);
            switch (ret) {
            case 0:
                goto retry;
            }
            // [...]
        }
    }
    // [...]
}

static int check_vma_flags(struct vm_area_struct *vma, unsigned long gup_flags)
{
    vm_flags_t vm_flags = vma->vm_flags;
    int write = (gup_flags & FOLL_WRITE);
    int foreign = (gup_flags & FOLL_REMOTE);

    // [...]
    if (write) {
        if (!(vm_flags & VM_WRITE)) {
            if (!(gup_flags & FOLL_FORCE)) // [9]
                return -EFAULT;

            if (!is_cow_mapping(vm_flags)) // [10]
                return -EFAULT;
        }
    }
}

static inline bool is_cow_mapping(vm_flags_t flags)
{
    return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}
```

Finally, `follow_page_mask()` is what walks the page table to find the `struct page` for the given address.

But if the page hasn't been faulted in yet, it returns NULL, and the kernel falls back to `faultin_page()` to bring it into memory.

### 2.2. First Page Access

When the kernel needs to load a page for the first time, it calls `faultin_page()`, which eventually ends up in `handle_pte_fault()` [1] to deal with setting up the PTE.

``` c
static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
        unsigned long address, unsigned int *flags, int *nonblocking)
{
    unsigned int fault_flags = 0;
    vm_fault_t ret;

    // [...]
    ret = handle_mm_fault(vma, address, fault_flags /* FAULT_FLAG_WRITE | FAULT_FLAG_REMOTE */); // <----------------
    
    // [...]
    if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
        *flags &= ~FOLL_WRITE;
    
    return 0;
}

int handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
        unsigned int flags)
{
    // [...]
    ret = __handle_mm_fault(vma, address, flags); // <----------------
    // [...]
}

static int __handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
        unsigned int flags)
{
    struct fault_env fe = {
        .vma = vma,
        .address = address,
        .flags = flags,
    };
    
    // ... handle pgd, pud and pmd
    return handle_pte_fault(&fe); // [1]
}
```

Inside `handle_pte_fault()`, if the page table doesn't yet have a valid PTE for the address [2], it falls into `do_fault()` to actually bring in the page [3].

``` c
static int handle_pte_fault(struct fault_env *fe)
{
    if (unlikely(pmd_none(*fe->pmd))) { // [2]
        fe->pte = NULL;
    } else {
        // [...]
    }

    if (!fe->pte) {
        // [...]
        else
            return do_fault(fe); // [3]
    }
    // [...]
}
```

If the memory is a COW mapping, `do_fault()` will call `do_cow_fault()`, which in turn calls `__do_fault()` [4] to load the actual page. After that, the original memory content is copied to a newly created page [5], which serves as the COW page. Finally, the PTE is updated to reference to the new page [6].

``` c
static int do_fault(struct fault_env *fe)
{
    struct vm_area_struct *vma = fe->vma;
    // [...]
    if (!(vma->vm_flags & VM_SHARED))
        return do_cow_fault(fe, pgoff); // <----------------
    // [...]
}

static int do_cow_fault(struct fault_env *fe, pgoff_t pgoff)
{
    struct vm_area_struct *vma = fe->vma;
    
    // [...]
    new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, fe->address);
    
    // [...]
    ret = __do_fault(fe, pgoff, new_page, &fault_page, &fault_entry); // [4]
    copy_user_highpage(new_page, fault_page, fe->address, vma); // [5]
    
    // [...]
    ret |= alloc_set_pte(fe, memcg, new_page); // [6]
    
    // [...]
    return ret;
}
```

If it's a file mapping, the kernel will call the file's fault handler, `filemap_fault()` [7], to get the memory page of the mapped file for COW.

``` c
static int __do_fault(struct fault_env *fe, pgoff_t pgoff,
        struct page *cow_page, struct page **page, void **entry)
{
    struct vm_area_struct *vma = fe->vma;
    // [...]
    ret = vma->vm_ops->fault(vma, &vmf); // [7], `filemap_fault()`
    // [...]
    *page = vmf.page;
    return ret;
}
```

In short, when the `faultin_page()` is first called, the kernel doesn't actually check whether the access is read or write. It just sets up the PTE to point to the COW page.

### 2.3. Second Page Access

Since no permission checks are done during the first call to `faultin_page()`, it just returns 0 and the flow jumps back to retrying `follow_page_mask()`.

``` c
long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
        unsigned long start, unsigned long nr_pages,
        unsigned int gup_flags, struct page **pages,
        struct vm_area_struct **vmas, int *nonblocking)
{
    // [...]
retry:
    // [...]
    page = follow_page_mask(vma, start, foll_flags, &page_mask);
    if (!page) {
        int ret;
        ret = faultin_page(tsk, vma, start, &foll_flags,
                nonblocking);
        switch (ret) {
        case 0:
            goto retry;
        }
        // [...]
    }
}
```

Now this time, there's a valid PTE, but since the request includes a write (`FOLL_WRITE`) and the PTE isn't marked writable [1], `follow_page_mask()` still returns NULL [2].

``` c
struct page *follow_page_mask(struct vm_area_struct *vma,
                  unsigned long address, unsigned int flags,
                  unsigned int *page_mask)
{
    // [...]
    return follow_page_pte(vma, address, pmd, flags); // <----------------
}

static struct page *follow_page_pte(struct vm_area_struct *vma,
        unsigned long address, pmd_t *pmd, unsigned int flags)
{
    // [...]
    ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
    pte = *ptep;
    
    // [...]
    if ((flags & FOLL_WRITE) && !pte_write(pte)) { // [1]
        pte_unmap_unlock(ptep, ptl);
        return NULL; // [2]
    }
}
```

So the kernel retries `faultin_page()` again. But this time, since there's already a valid PTE, the kernel skips creating one and instead **checks access permissions**.

If it's a write fault [3] and the PTE doesn't allow writing [4], it triggers the COW mechanism by calling `do_wp_page()` to handle write-protected pages.

``` c
static int handle_pte_fault(struct fault_env *fe)
{
    if (unlikely(pmd_none(*fe->pmd))) {
        // [...]
    } else {
        fe->pte = pte_offset_map(fe->pmd, fe->address);
        entry = *fe->pte;
    }

    fe->ptl = pte_lockptr(fe->vma->vm_mm, fe->pmd);
    spin_lock(fe->ptl);
    // [...]
    if (fe->flags & FAULT_FLAG_WRITE) { // [3]
        if (!pte_write(entry)) // [4]
            return do_wp_page(fe, entry);
        // [...]
    }
    // [...]
}
```

Inside `do_wp_page()`, if it's an anonymous mapping (i.e., not shared memory or file-backed), it calls `wp_page_reuse()` to handle the fault. This function just marks the page as dirty and accessed, and returns `VM_FAULT_WRITE` [5].

``` c
static int do_wp_page(struct fault_env *fe, pte_t orig_pte)
    __releases(fe->ptl)
{
    // [...]
    old_page = vm_normal_page(vma, fe->address, orig_pte);
    if (PageAnon(old_page) && !PageKsm(old_page)) {
        // [...]
        unlock_page(old_page);
        return wp_page_reuse(fe, orig_pte, old_page, 0, 0); // <----------------
    }
}

static inline int wp_page_reuse(struct fault_env *fe, pte_t orig_pte,
            struct page *page, int page_mkwrite, int dirty_shared)
    __releases(fe->ptl)
{
    // [...]
    entry = pte_mkyoung(orig_pte); // set `_PAGE_ACCESSED`
    pte_mkdirty(entry);            // set `_PAGE_DIRTY` | `_PAGE_SOFT_DIRTY`
    // [...]
    pte_unmap_unlock(fe->pte, fe->ptl);
    return VM_FAULT_WRITE; // [5]
}
```

Once `faultin_page()` finishes and sees that `handle_mm_fault()` returned `VM_FAULT_WRITE`, it knows the write fault was valid.

However, if the VMA doesn't have `VM_WRITE` permission [6], the kernel simply clears the `FOLL_WRITE` flag [7], allowing the rest of the flow to **treat it as a read access**.

``` c
static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
        unsigned long address, unsigned int *flags, int *nonblocking)
{
    unsigned int fault_flags = 0;
    vm_fault_t ret;

    // [...]
    ret = handle_mm_fault(vma, address, fault_flags /* FAULT_FLAG_WRITE | FAULT_FLAG_REMOTE */);
    
    // [...]
    if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE)) // [6]
        *flags &= ~FOLL_WRITE; // [7]
    
    return 0;
}
```

The heart of the Dirty COW issue lies here: **although it's a write operation, the kernel downgrades it to a read by clearing `FOLL_WRITE`, setting the stage for a race condition**.

### 2.4. Third Page Access

Since `faultin_page()` returns 0 again, the kernel moves on to a **third call** to `follow_page_mask()`. The flow is the same as before - but this time, because the `FOLL_WRITE` flag has been cleared, `follow_page_pte()` no longer checks whether the PTE is writable [1]. It just grabs the page and returns it directly [2].

``` c
static struct page *follow_page_pte(struct vm_area_struct *vma,
        unsigned long address, pmd_t *pmd, unsigned int flags)
{
    // [...]
    ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
    pte = *ptep;
    
    // [...]
    if ((flags & FOLL_WRITE) && !pte_write(pte)) { // [1]
        // [...]
    }

    // [...]
    page = vm_normal_page(vma, address, pte);

    // [...]
    pte_unmap_unlock(ptep, ptl);
    return page; // [2]
}
```

## 3. Vulnerability

### 3.1. Memory Advice

The `SYS_madvise` syscall allows user processes to give the kernel hints about how they plan to use memory. Depending on the advice provided, the kernel takes different actions. At the start of the syscall, the kernel grabs a read or write lock on the `current->mm`, depending on the type of advice [1].

When the advice is `MADV_DONTNEED`, it tells the kernel: "I won't be using this memory for a while." This hint is handled by the `madvise_dontneed()` function [2].

``` c
SYSCALL_DEFINE3(madvise, unsigned long, start, size_t, len_in, int, behavior)
{
    // [...]
    write = madvise_need_mmap_write(behavior); // [1], return 0 if `MADV_DONTNEED`
    if (write) {
        if (down_write_killable(&current->mm->mmap_sem))
            return -EINTR;
    } else {
        down_read(&current->mm->mmap_sem);
    }

    // [...]
    vma = find_vma_prev(current->mm, start, &prev);
    
    // [...]
    for (;;) {
        // [...]
        error = madvise_vma(vma, &prev, start, tmp, behavior); // <----------------
        // [...]
    }
}

static long
madvise_vma(struct vm_area_struct *vma, struct vm_area_struct **prev,
        unsigned long start, unsigned long end, int behavior)
{
    switch (behavior) {
    // [...]
    case MADV_DONTNEED:
        return madvise_dontneed(vma, prev, start, end); // [2]
    // [...]
    }
}
```

In `madvise_dontneed()`, the kernel clears out the pages in the specified memory range using `zap_page_range()` [3]. If the process tries to access them again later, they'll be faulted back in as needed.

``` c
static long madvise_dontneed(struct vm_area_struct *vma,
                 struct vm_area_struct **prev,
                 unsigned long start, unsigned long end)
{
    *prev = vma;
    // [...]
    zap_page_range(vma, start, end - start, NULL); // [3]
    return 0;
}
```

Function `zap_page_range()` walks through the VMAs that overlap with the given address range [4]. For each one, it eventually calls `unmap_page_range()` [5] to zero out the page table entries.

``` c
void zap_page_range(struct vm_area_struct *vma, unsigned long start,
        unsigned long size, struct zap_details *details)
{
    struct mm_struct *mm = vma->vm_mm;
    struct mmu_gather tlb;
    unsigned long end = start + size;

    // [...]
    for ( ; vma && vma->vm_start < end; vma = vma->vm_next)
        unmap_single_vma(&tlb, vma, start, end, details); // [4]
    // [...]
}

static void unmap_single_vma(struct mmu_gather *tlb,
        struct vm_area_struct *vma, unsigned long start_addr,
        unsigned long end_addr,
        struct zap_details *details)
{
    if (start != end) {
        // [...]
        unmap_page_range(tlb, vma, start, end, details); // [5], zero out page table        
    }
}
```

Because the `SYS_madvise(MADV_DONTNEED)` only acquires a read lock on `mm`, it is possible to zero out those COW pages concurrently.

### 3.2. Race Condition

If another thread clears the PTE between the second and third page access, the operation will start over without the `FOLL_WRITE` flag, so it behaves like a read access instead of a write access.

The expected execution flow for triggering the race condition is as follows:

```
[Thread-1]                                           [Thread-2]
__get_user_pages
  follow_page_mask
    -> no PTE
  faultin_page
    -> faults in a new COW page with file content
  cond_resched
    -> context switch

  [...]

  follow_page_mask
    -> page lacks write permission
  faultin_page
    -> clears FOLL_WRITE flag (treat as read)
  cond_resched
    -> context switch

  [...]
                                                     SYS_madvise(MADV_DONTNEED)
                                                       -> zeroes out PTEs
  [...]

  follow_page_mask
    -> no PTE
  faultin_page (w/o FOLL_WRITE)
    do_read_fault
      -> faults in a direct file mapping
  cond_resched
    -> context switch

  [...]

  follow_page_mask
    -> returns file-backed page
```

### 3.3. Read Fault

When `FOLL_WRITE` is not set, the kernel treats the page fault as a read. In that case, `do_fault()` dispatches the fault handling to `do_read_fault()` [1].

``` c
static int do_fault(struct fault_env *fe)
{
    struct vm_area_struct *vma = fe->vma;
    // [...]
    if (!(fe->flags & FAULT_FLAG_WRITE))
        return do_read_fault(fe, pgoff); // [1]
    // [...]
}
```

Inside `do_read_fault()`, the kernel eventually calls into the filesystem's page mapping handler [2]. While different filesystems may implement this differently, for most common ones, the `vm_ops->map_pages` function points to `filemap_map_pages()`

This function retrieves the **mapped page** from the pagecache, which is set up when mounting a filesystem.

``` c
static int do_read_fault(struct fault_env *fe, pgoff_t pgoff)
{
    struct vm_area_struct *vma = fe->vma;
    struct page *fault_page;
    int ret = 0;

    // [...]
    if (vma->vm_ops->map_pages && /* ... */) {
        ret = do_fault_around(fe, pgoff); // <----------------
        if (ret)
            return ret;
    }
    // [...]
}

static int do_fault_around(struct fault_env *fe, pgoff_t start_pgoff)
{
    // [...]
    if (pmd_none(*fe->pmd)) {
        fe->prealloc_pte = pte_alloc_one(fe->vma->vm_mm, fe->address);
        // [...]
    }

    // [...]
    fe->vma->vm_ops->map_pages(fe, start_pgoff, end_pgoff); // [2], `filemap_map_pages()`
    if (!pte_none(*fe->pte))
        ret = VM_FAULT_NOPAGE; // 0x100

    // [...]
    fe->address = address;
    fe->pte = NULL;
    return ret;
}
```

Finally, the PTE points to the **file-mapped page rather than a COW page**, so any modifications will **directly update the underlying file content**.

## 4. Patch

After the patch, the kernel no longer clears the `FOLL_WRITE` flag when a COW happens. Instead, it introduces a new internal flag called `FOLL_COW`.

``` diff
+#define FOLL_COW 0x4000 /* internal GUP flag */

@@ -412,7 +422,7 @@ static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
      * reCOWed by userspace write).
      */
     if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
-        *flags &= ~FOLL_WRITE;
+        *flags |= FOLL_COW;
     return 0;
```

When mapping the page, the kernel now performs stricter checks. In addition to verifying that it's a COW scenario, it also checks that the target PTE is **marked dirty** before allowing write access.

``` diff
+static inline bool can_follow_write_pte(pte_t pte, unsigned int flags)
+{
+    return pte_write(pte) ||
+        ((flags & FOLL_FORCE) && (flags & FOLL_COW) && pte_dirty(pte));
+}

static struct page *follow_page_pte(struct vm_area_struct *vma,
         unsigned long address, pmd_t *pmd, unsigned int flags)
 {
@@ -95,7 +105,7 @@ retry:
     }
     if ((flags & FOLL_NUMA) && pte_protnone(pte))
         goto no_page;
-    if ((flags & FOLL_WRITE) && !pte_write(pte)) {
+    if ((flags & FOLL_WRITE) && !can_follow_write_pte(pte, flags)) {
         pte_unmap_unlock(ptep, ptl);
         return NULL;
     }
```

## 5. Others

Under normal conditions, how does the kernel prevent **dirty pages** from a **private file mapping** from being written back to the file?

Looking at the implementation of `SYS_msync`, we can see that data is only synced back to the file if the VMA has the `VM_SHARED` flag set [1]. In other words, only shared mappings will trigger writeback.

If the mapping was created with `MAP_PRIVATE`, the `VM_SHARED` flag won't be set on the VMA - meaning any modifications stay in memory and never reach the underlying file.

``` c
SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
{
    // [...]
    if ((flags & MS_SYNC) && file && (vma->vm_flags & VM_SHARED)) { // [1]
        get_file(file);
        mmap_read_unlock(mm);
        error = vfs_fsync_range(file, fstart, fend, 1);
        fput(file);
        // [...]
        mmap_read_lock(mm);
        vma = find_vma(mm, start);
    }
    // [...]
}
```
