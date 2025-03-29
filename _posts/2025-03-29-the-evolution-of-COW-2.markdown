---
layout: post
title:  "The Evolution of Dirty COW (2)"
categories: linux
---

- Part1: [The Evolution of Dirty COW (1)]({% post_url 2025-03-27-the-evolution-of-COW-1 %})
- Part2: [The Evolution of Dirty COW (2)]({% post_url 2025-03-29-the-evolution-of-COW-2 %})

In this post, we're continuing our deep dive into Dirty COW by exploring two of its known variants: Huge Dirty COW and SHM (Shared Memory) Dirty COW.

## 1. CVE-2017–1000405 (Huge Dirty COW): mm, thp: Do not make page table dirty unconditionally in touch_p[mu]d()
> Reference
> 1. https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a8f97366452ed491d13cf1e44241bc0b5740b1f0
> 2. https://medium.com/bindecy/huge-dirty-cow-cve-2017-1000405-110eca132de0

The researcher who discovered this bug has a great [write-up](https://medium.com/bindecy/huge-dirty-cow-cve-2017-1000405-110eca132de0) explaining the root cause, exploitation scenarios, and additional details - highly recommend giving it a read.

### 1.1. Huge Page Overview

By default, Linux uses 4KB page sizes. But modern CPUs support much larger page sizes - 2MB or even 1GB. These are called **huge pages**. To take advantage of the performance boost that huge pages can offer, Linux provides two mechanisms to manage them: **hugetlb** and **THP (Transparent Huge Pages)**.

#### hugetlb

The first mechanism is **hugetlb**, which allows user programs to explicitly request huge pages using the `SYS_mmap` system call with the `MAP_HUGETLB` flag [1]. You can also specify the exact size with flags like `MAP_HUGE_2MB` or `MAP_HUGE_1GB`.

``` c
SYSCALL_DEFINE6(mmap_pgoff, unsigned long, addr, unsigned long, len,
        unsigned long, prot, unsigned long, flags,
        unsigned long, fd, unsigned long, pgoff)
{
    struct file *file = NULL;
    unsigned long retval;

    // [...]
    else if (flags & MAP_HUGETLB) { // [1]
        struct user_struct *user = NULL;
        struct hstate *hs;

        hs = hstate_sizelog((flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
        len = ALIGN(len, huge_page_size(hs));
        file = hugetlb_file_setup(HUGETLB_ANON_FILE, len,
                VM_NORESERVE,
                &user, HUGETLB_ANONHUGE_INODE,
                (flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
    }

    // [...]
    retval = vm_mmap_pgoff(file, addr, len, prot, flags, pgoff);
    // [...]
    return retval;
}
```

However, hugetlb pages aren’t dynamically allocated. They need to be pre-reserved at boot via `hugetlb_hstate_alloc_pages()`, and in most environments, none are allocated by default. You can check the number of reserved huge pages via `/proc/sys/vm/nr_hugepages`.

``` c
static void __init hugetlb_hstate_alloc_pages(struct hstate *h)
{
    unsigned long i;

    for (i = 0; i < h->max_huge_pages; ++i) {
        if (hstate_is_gigantic(h)) {
            if (!alloc_bootmem_huge_page(h)) // <-------------------
                break;
        } else if (!alloc_fresh_huge_page(h, // <-------------------
                     &node_states[N_MEMORY]))
            break;
        cond_resched();
    }
    // [...]
}
```

#### THP

The second mechanism is **THP**, which is handled automatically by the kernel. Processes don't need to do anything special, though they can still hint the kernel to use THPs for a memory range. This is especially useful for apps like QEMU that manage large chunks of memory.

When a process keeps allocating anonymous memory, the kernel's mmap handler may try to collapse these into huge pages, depending on kernel config. If `CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS=y` is set, the conversion passes the check in `hugepage_vma_check()` [1].

``` c
static unsigned long __mmap_region(struct file *file, unsigned long addr,
        unsigned long len, vm_flags_t vm_flags, unsigned long pgoff,
        struct list_head *uf)
{
    // [..]
    if (vma &&
        !vma_expand(&vmi, vma, merge_start, merge_end, vm_pgoff, next)) {
        khugepaged_enter_vma(vma, vm_flags); // <-------------------
        goto expanded;
    }
    // [...]
}

void khugepaged_enter_vma(struct vm_area_struct *vma,
              unsigned long vm_flags)
{
    if (!test_bit(MMF_VM_HUGEPAGE, &vma->vm_mm->flags) &&
        hugepage_flags_enabled()) {
        if (hugepage_vma_check(vma, vm_flags, false, false, true /* enforce_sysfs */)) // <-------------------
            __khugepaged_enter(vma->vm_mm); // [2]
    }
}

bool hugepage_vma_check(struct vm_area_struct *vma, unsigned long vm_flags,
            bool smaps, bool in_pf, bool enforce_sysfs)
{
    // [...]
    if (enforce_sysfs &&
        (!hugepage_flags_enabled() || (!(vm_flags & VM_HUGEPAGE) &&
                       !hugepage_flags_always()))) // [1]
        return false;
    // [...]
}
```

If THP conversion is approved, the kernel calls `__khugepaged_enter()`[2] to queue the request for the `khugepaged` kernel thread [3].

``` c
void __khugepaged_enter(struct mm_struct *mm)
{
    struct khugepaged_mm_slot *mm_slot;

    // [...]
    mm_slot = mm_slot_alloc(mm_slot_cache);
    wakeup = list_empty(&khugepaged_scan.mm_head);
    list_add_tail(&slot->mm_node, &khugepaged_scan.mm_head);

    // [...]
    if (wakeup)
        wake_up_interruptible(&khugepaged_wait); // [4]
}
```

That thread wakes up [4] and handles the request via `khugepaged_do_scan()` [5].

``` c
static void khugepaged_wait_work(void)
{
    // [...]
    if (hugepage_flags_enabled())
        wait_event_freezable(khugepaged_wait, khugepaged_wait_event()); // [4]
}

static int khugepaged(void *none)
{
    struct khugepaged_mm_slot *mm_slot;

    // [...]
    while (!kthread_should_stop()) {
        khugepaged_do_scan(&khugepaged_collapse_control); // [5]
        khugepaged_wait_work();
    }
    // [...]
}
```

In setups where `CONFIG_TRANSPARENT_HUGEPAGE_MADVISE=y`, the process has to explicitly call `SYS_madvise(MADV_HUGEPAGE)` to request THPs. If the memory range passes some flag checks [6], it eventually triggers `khugepaged_enter()` [7].

``` c
static long madvise_behavior(struct vm_area_struct *vma,
             struct vm_area_struct **prev,
             unsigned long start, unsigned long end, int behavior)
{
    struct mm_struct *mm = vma->vm_mm;
    unsigned long new_flags = vma->vm_flags;
    // [...]

    switch (behavior) {
    // [...]
    case MADV_HUGEPAGE:
        error = hugepage_madvise(vma, &new_flags, behavior); // <-------------------
        // [...]
        break;
    }
}

#define VM_NO_KHUGEPAGED (VM_SPECIAL | VM_HUGETLB)
int hugepage_madvise(struct vm_area_struct *vma,
             unsigned long *vm_flags, int advice)
{
    switch (advice) {
    // [...]
    case MADV_HUGEPAGE:
        *vm_flags &= ~VM_NOHUGEPAGE;
        *vm_flags |= VM_HUGEPAGE;
        // [...]
        if (!(*vm_flags & VM_NO_KHUGEPAGED) && // [6]
                khugepaged_enter_vma_merge(vma, *vm_flags)) // <-------------------
            return -ENOMEM;
        break;
    // [...]
    }
}

int khugepaged_enter_vma_merge(struct vm_area_struct *vma,
                   unsigned long vm_flags)
{
    unsigned long hstart, hend;
    // [...]
    hstart = (vma->vm_start + ~HPAGE_PMD_MASK) & HPAGE_PMD_MASK;
    hend = vma->vm_end & HPAGE_PMD_MASK;
    if (hstart < hend)
        return khugepaged_enter(vma, vm_flags); // [7]
    return 0;
}
```

You can check which THP mode your system is using with this file:
``` bash
cat /sys/kernel/mm/transparent_hugepage/enabled
```
- Ubuntu: `always [madvise] never`
- RHEL9: `[always] madvise never`

#### khugepaged

The `khugepaged` kernel thread is responsible for collapsing memory ranges into huge pages in the background. It's a complex process, but the end result is that a range of pages is **merged into a PMD entry with the Page Size (PS) bit set** [1].

``` c
static void khugepaged_do_scan(struct collapse_control *cc)
{
    while (true) {
        // [...]
        if (khugepaged_has_work() &&
            pass_through_head < 2)
            progress += khugepaged_scan_mm_slot(pages - progress, // <-------------------
                                &result, cc);
        // [...]
    }
}

static unsigned int khugepaged_scan_mm_slot(unsigned int pages, int *result,
                        struct collapse_control *cc)
    __releases(&khugepaged_mm_lock)
    __acquires(&khugepaged_mm_lock)
{
    vma_iter_init(&vmi, mm, khugepaged_scan.address);
    for_each_vma(vmi, vma) {
        // [...]
        else {
            *result = hpage_collapse_scan_pmd(mm, vma, // <-------------------
                        khugepaged_scan.address, &mmap_locked, cc);
        }
        // [...]
    }
}

static int hpage_collapse_scan_pmd(struct mm_struct *mm,
                   struct vm_area_struct *vma,
                   unsigned long address, bool *mmap_locked,
                   struct collapse_control *cc)
{
    // [...]
    if (result == SCAN_SUCCEED) {
        result = collapse_huge_page(mm, address, referenced, // <-------------------
                        unmapped, cc);
        // [...]
    }
}

static int collapse_huge_page(struct mm_struct *mm, unsigned long address,
                  int referenced, int unmapped,
                  struct collapse_control *cc)
{
    // [...]
    _pmd = mk_huge_pmd(hpage, vma->vm_page_prot); // [1]
    _pmd = maybe_pmd_mkwrite(pmd_mkdirty(_pmd), vma);
    // [...]
}

#define mk_huge_pmd(page, prot) pmd_mkhuge(mk_pmd(page, prot))

static inline pmd_t pmd_mkhuge(pmd_t pmd)
{
    return pmd_set_flags(pmd, _PAGE_PSE);
}

#define _PAGE_BIT_PSE 7 /* 4 MB (or 2MB) page */
#define _PAGE_PSE (_AT(pteval_t, 1) << _PAGE_BIT_PSE)
```

### 1.2. Root Cause

The trigger path is largely similar to the original Dirty COW, but this time the target address points to a THP.

When `__get_user_pages()` is called, it eventually invokes `follow_page_mask()` to grab the page backing the given address. Under the hood, this walks down the page table hierarchy and lands in `follow_pmd_mask()` [1].

``` c
static long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
        unsigned long start, unsigned long nr_pages,
        unsigned int gup_flags, struct page **pages,
        struct vm_area_struct **vmas, int *nonblocking)
{
    // [...]
retry:
    // [...]
    page = follow_page_mask(vma, start, foll_flags, &page_mask); // <-------------------
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

struct page *follow_page_mask(struct vm_area_struct *vma,
                  unsigned long address, unsigned int flags,
                  unsigned int *page_mask)
{
    struct mm_struct *mm = vma->vm_mm;
    pgd = pgd_offset(mm, address);
    
    // [...]
    return follow_p4d_mask(vma, address, pgd, flags, page_mask); // <-------------------
}

static struct page *follow_p4d_mask(struct vm_area_struct *vma,
                    unsigned long address, pgd_t *pgdp,
                    unsigned int flags, unsigned int *page_mask)
{
    p4d = p4d_offset(pgdp, address);
    // [...]
    return follow_pud_mask(vma, address, p4d, flags, page_mask); // <-------------------
}

static struct page *follow_pud_mask(struct vm_area_struct *vma,
                    unsigned long address, p4d_t *p4dp,
                    unsigned int flags, unsigned int *page_mask)
{
    pud = pud_offset(p4dp, address);
    // [...]
    return follow_pmd_mask(vma, address, pud, flags, page_mask); // [1]
}
```

We skipped some details about part getting page the previous Dirty COW post. Actually, function `follow_pmd_mask()` decides which handler to call depending on the type of memory backing the address - whether it's a hugetlb page [2], regular page [3], or a THP [4].

``` c
static struct page *follow_pmd_mask(struct vm_area_struct *vma,
                    unsigned long address, pud_t *pudp,
                    unsigned int flags, unsigned int *page_mask)
{

    struct mm_struct *mm = vma->vm_mm;

    if (pmd_huge(*pmd) && vma->vm_flags & VM_HUGETLB) { // [2], hugetlb page case
        page = follow_huge_pmd(mm, address, pmd, flags);
        if (page)
            return page;
        // [...]
    }

    // [...]
    if (likely(!pmd_trans_huge(*pmd))) // [3], normal page
        return follow_page_pte(vma, address, pmd, flags);

    // [...]
    page = follow_trans_huge_pmd(vma, address, pmd, flags); // [4], THP
    
    // [...]
    return page;
}
```

If the target is a THP, it calls `follow_trans_huge_pmd()`. This function first checks whether the current access is a write operation [5]. If it is, it then ensures that the PMD has write permissions [6], or that the situation satisfies the COW logic [7].

By the way, the helper `can_follow_write_pmd()` was originally vulnerable to Dirty COW behavior but was later fixed in [this commit](https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8310d48b125d)。

``` c
struct page *follow_trans_huge_pmd(struct vm_area_struct *vma,
                   unsigned long addr,
                   pmd_t *pmd,
                   unsigned int flags)
{
    // [...]
    if (flags & FOLL_WRITE /* [5] */ && !can_follow_write_pmd(*pmd, flags))
        goto out;

    // [...]
    page = pmd_page(*pmd);
    
    // [...]
    if (flags & FOLL_TOUCH) // [8]
        touch_pmd(vma, addr, pmd);
    
    // [...]
    return page;
}

static inline bool can_follow_write_pmd(pmd_t pmd, unsigned int flags)
{
    return pmd_write(pmd) || // [6]
           ((flags & FOLL_FORCE) && (flags & FOLL_COW) && pmd_dirty(pmd)); // [7]
}
```

If the flags include `FOLL_TOUCH`, the kernel calls `touch_pmd()` [8], and this flag is set when accessing remote virtual memory via `/proc/self/mem`.

However, `touch_pmd()` **sets the dirty and accessed bits in the PMD entry without performing any checks**, even if it's just a read access to a read-only page.

``` c
static void touch_pmd(struct vm_area_struct *vma, unsigned long addr,
        pmd_t *pmd)
{
    pmd_t _pmd;

    // [...]
    _pmd = pmd_mkyoung(pmd_mkdirty(*pmd)); // set `_PAGE_DIRTY` | `_PAGE_ACCESSED`
    pmdp_set_access_flags(vma, addr & HPAGE_PMD_MASK,
                pmd, _pmd, 1);
    // [...]
}
```

Unfortunately, a **read access to a read-only THP** can unintentionally **set the dirty bit in the PTE**. This breaks the assumption made by `can_follow_write_pmd()`: that **the dirty bit is only set when the target page is writable**.

### 1.3. Race Condition

Since this vulnerability can only be triggered through THP, and most filesystems don't support THP, its impact isn't as widespread as something like Dirty COW.

In the PoC, the author targets the huge zero page. Thread-1 detects a COW fault and prepares to handle it. However, right before the COW page is fully set up, there's a race condition - Thread-2 steps in, replaces the COW page with a huge zero page, and triggers a remote read access that ends up marking the PTE as dirty.

When the context switches back to Thread-1, `can_follow_write_pmd()` checks the PTE and sees the dirty bit set, so it assumes the page is writable and returns it. Consequently, the data is written directly into the huge zero page.

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
    follow_trans_huge_pmd
      -> page lacks write permission
  faultin_page
    -> sets FOLL_COW flag
  cond_resched
    -> context switch

  [...]

                                                     SYS_madvise(MADV_DONTNEED)
                                                       -> zeroes out the COW PTE
                                                     read access THP
                                                       -> load the PTE of the read-only huge zero page
                                                     remote access THP via /proc/self/mem
                                                       __get_user_pages
                                                         follow_trans_huge_pmd
                                                           touch_pmd
                                                             -> marks the PTE as dirty

  [...]

  follow_page_mask
    follow_trans_huge_pmd
      -> bypasses can_follow_write_pmd()
      -> directly writes data to the read-only huge zero page
```

### 1.4. Huge Zero Page

When anonymous memory is read-only, the kernel doesn't actually allocate a physical page during a page fault. Instead, it maps in a shared zero page that's used by all processes. Since the memory region isn't writable, its content is always zero, so there's no need to waste memory allocating real pages full of zeros.

The function `__handle_mm_fault()` is the page fault handler. If the target PMD is empty and THP is enabled [1], it calls `create_huge_pmd()` to allocate a huge page PMD.

``` c
static int __handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
        unsigned int flags)
{
    struct vm_fault vmf = {
        .vma = vma,
        .address = address & PAGE_MASK,
        .flags = flags,
        .pgoff = linear_page_index(vma, address),
        .gfp_mask = __get_fault_gfp_mask(vma),
    };

    // [...]
    vmf.pmd = pmd_alloc(mm, vmf.pud, address);
    if (pmd_none(*vmf.pmd) && transparent_hugepage_enabled(vma)) { // [1]
        ret = create_huge_pmd(&vmf); // <-------------------
        // [...]
    }
    // [...]
}

static inline int create_huge_pmd(struct vm_fault *vmf)
{
    if (vma_is_anonymous(vmf->vma))
        return do_huge_pmd_anonymous_page(vmf); // <-------------------
    // [..]
}
```

That leads to `do_huge_pmd_anonymous_page()` being called. If it detects a read access [2], it fetches the huge zero page [3] and installs it into the PMD [4].

``` c
int do_huge_pmd_anonymous_page(struct vm_fault *vmf)
{
    // [...]
    if (!(vmf->flags & FAULT_FLAG_WRITE) && // [2], a read access
            /* ... */ &&
            transparent_hugepage_use_zero_page()) {
        pgtable_t pgtable;
        struct page *zero_page;
        bool set;
        int ret;

        pgtable = pte_alloc_one(vma->vm_mm, haddr);
        zero_page = mm_get_huge_zero_page(vma->vm_mm); // [3]
        // [...]
        vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
        if (pmd_none(*vmf->pmd)) {
            set_huge_zero_page(pgtable, vma->vm_mm, vma, // [4]
                        haddr, vmf->pmd, zero_page);
            // [...]
        }
        // [...]
        return ret;
    }
}

struct page *mm_get_huge_zero_page(struct mm_struct *mm)
{
    // [...]
    return READ_ONCE(huge_zero_page);
}
```

As mentioned earlier, the huge zero page is filled with zeros and **shared across all processes**. So if an attacker writes arbitrary data to it, this breaks the assumption that it's always zero, potentially causing **crashes** or **unexpected behavior** in other processes that rely on it.

### 1.5. Patch

The patch is actually quite straightforward - only set the dirty bit if the request is a write access.

``` diff
 static void touch_pmd(struct vm_area_struct *vma, unsigned long addr,
-        pmd_t *pmd)
+        pmd_t *pmd, int flags)
 {
     pmd_t _pmd;
 
// [...]
+    if (flags & FOLL_WRITE)
+        _pmd = pmd_mkdirty(_pmd);
```

## 2. CVE-2022-2590 (SHM Dirty COW): mm/gup: fix FOLL_FORCE COW security issue and remove FOLL_COW
> Reference
> 1. https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5535be3099717646781ce1540cf725965d680e7b
> 2. https://github.com/hyeonjun17/CVE-2022-2590-analysis
> 3. https://seclists.org/oss-sec/2022/q3/99

The GitHub repo [CVE-2022-2590-analysis](https://github.com/hyeonjun17/CVE-2022-2590-analysis) gives a nice overview of the vulnerability and shows the call flow that triggers it. I relied heavily on that resource while writing this - highly recommend checking it out.

### 2.1. Overview

This vulnerability was introduced in this [commit](https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9ae0f87d009ca6c4aab2882641ddfc319727e3db). After this patch, the function `mfill_atomic_install_pte()` would always mark the target PTE as dirty, regardless of whether the VMA had `VM_WRITE` permissions or if the page was actually in the page cache.

``` diff
@@ -69,10 +69,9 @@ int mfill_atomic_install_pte(struct mm_struct *dst_mm, pmd_t *dst_pmd,
     pgoff_t offset, max_off;
 
     _dst_pte = mk_pte(page, dst_vma->vm_page_prot);
+    _dst_pte = pte_mkdirty(_dst_pte);
     if (page_in_cache && !vm_shared)
         writable = false;
-    if (writable || !page_in_cache)
-        _dst_pte = pte_mkdirty(_dst_pte);
```

Let's take a quick detour to talk about userfaultfd. It's a mechanism that **allows user space to handle its own page faults**. You start by calling `SYS_userfaultfd()` [1] to get a file descriptor, then use `SYS_ioctl()` to interact with the userfaultfd subsystem.

According to the [man page](https://man7.org/linux/man-pages/man2/userfaultfd.2.html), when userfaultfd is set to `UFFDIO_REGISTER_MODE_MINOR` [2] mode, the kernel will notify the user space handler only when a **minor page fault** occurs.

``` c
int uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK); // [1]
// [...]

struct uffdio_register uffdio_register = {
    .range.start = (unsigned long)addr,
    .range.len = PAGE_SIZE,
    .mode = UFFDIO_REGISTER_MODE_MINOR, // [2]
};
ioctl(uffd, UFFDIO_REGISTER, &uffdio_register);

// [...]
```

So what's a minor page fault? When you first access a memory-mapped file, the system triggers a page fault to fetch the data. If that data is **already in RAM**, it just **maps the page** and continues - that's a minor fault.

But if the data's still on disk (or has been swapped out), the kernel has to load it into RAM, and that's a major fault.

To avoid major faults, filesystems like EXT4 try to keep frequently used data in the page cache. When a process requests the data, the kernel can serve it straight from memory. To flush modified data back to disk, you can use `SYS_sync()` or similar calls.

The hierarchy of file access in Linux is as follows:

```
User Space
   ↓
VFS (Virtual File System)
   ↓
Filesystem (e.g. EXT4)
   ↓
Page Cache
   ↓
Block Layer (Bio, I/O Scheduler, etc.)
   ↓
Disk Driver
   ↓
Disk (SSD/HDD)
```

### 2.2. Root Cause

If a shared memory page fault occurs and the requested data is found in the filemap (aka page cache), the kernel notifies userfaultfd of a **minor page fault** [1].

``` c
static const struct vm_operations_struct shmem_vm_ops = {
    .fault = shmem_fault, // <-------------------
    // [...]
};

static vm_fault_t shmem_fault(struct vm_fault *vmf)
{
    // [...]
    err = shmem_getpage_gfp(inode, vmf->pgoff, &vmf->page, SGP_CACHE, // <-------------------
                  gfp, vma, vmf, &ret);
    // [...]
}

static int shmem_getpage_gfp(struct inode *inode, pgoff_t index,
    struct page **pagep, enum sgp_type sgp, gfp_t gfp,
    struct vm_area_struct *vma, struct vm_fault *vmf,
            vm_fault_t *fault_type)
{
    // [...]
    folio = __filemap_get_folio(mapping, index, FGP_ENTRY | FGP_LOCK, 0);
    if (folio && vma && userfaultfd_minor(vma)) {
        // [...]
        *fault_type = handle_userfault(vmf, VM_UFFD_MINOR); // [1]
        return 0;
    }
}
```

Once in user space, the user page fault handler can use the `UFFDIO_CONTINUE` ioctl command to tell the kernel to resume execution and resolve the minor fault.

``` c
static long userfaultfd_ioctl(struct file *file, unsigned cmd,
                  unsigned long arg)
{
    switch(cmd) {
    // [...]
    case UFFDIO_CONTINUE:
        ret = userfaultfd_continue(ctx, arg);
        break;
    // [...]
    }
}
```

`userfaultfd_continue()` grabs the target memory range from user input, then calls `mcopy_continue()` [2], which eventually calls `mfill_atomic_pte()` [3] to install the PTE.

``` c
static int userfaultfd_continue(struct userfaultfd_ctx *ctx, unsigned long arg)
{
    // [...]
    user_uffdio_continue = (struct uffdio_continue __user *)arg;
    copy_from_user(&uffdio_continue, user_uffdio_continue,
               sizeof(uffdio_continue) - (sizeof(__s64)));
    
    // [...]
    if (mmget_not_zero(ctx->mm)) {
        ret = mcopy_continue(ctx->mm, uffdio_continue.range.start, // [2]
                     uffdio_continue.range.len,
                     &ctx->mmap_changing);
    }
    // [...]
}

ssize_t mcopy_continue(struct mm_struct *dst_mm, unsigned long start,
               unsigned long len, atomic_t *mmap_changing)
{
    return __mcopy_atomic(dst_mm, start, 0, len, MCOPY_ATOMIC_CONTINUE, // <-------------------
                  mmap_changing, 0);
}

static __always_inline ssize_t __mcopy_atomic(struct mm_struct *dst_mm,
                          unsigned long dst_start,
                          unsigned long src_start,
                          unsigned long len,
                          enum mcopy_atomic_mode mcopy_mode,
                          atomic_t *mmap_changing,
                          __u64 mode)
{
    // [...]
    dst_vma = find_dst_vma(dst_mm, dst_start, len);

    while (src_addr < src_start + len) {
        // [...]
        dst_pmd = mm_alloc_pmd(dst_mm, dst_addr);

        // [...]
        err = mfill_atomic_pte(dst_mm, dst_pmd, dst_vma, dst_addr, // [3]
                       src_addr, &page, mcopy_mode, wp_copy);
        // [...]
    }
}
```

Eventually, we hit `mcontinue_atomic_pte()`, which first uses `shmem_getpage()` [4] to fetch the shared memory page, then calls `mfill_atomic_install_pte()` [5] to install it into the page table.

``` c
static __always_inline ssize_t mfill_atomic_pte(struct mm_struct *dst_mm,
                        pmd_t *dst_pmd,
                        struct vm_area_struct *dst_vma,
                        unsigned long dst_addr,
                        unsigned long src_addr,
                        struct page **page,
                        enum mcopy_atomic_mode mode,
                        bool wp_copy)
{
    ssize_t err;

    if (mode == MCOPY_ATOMIC_CONTINUE) {
        return mcontinue_atomic_pte(dst_mm, dst_pmd, dst_vma, dst_addr, // <-------------------
                        wp_copy);
    }
    // [...]
}

static int mcontinue_atomic_pte(struct mm_struct *dst_mm,
                pmd_t *dst_pmd,
                struct vm_area_struct *dst_vma,
                unsigned long dst_addr,
                bool wp_copy)
{
    struct inode *inode = file_inode(dst_vma->vm_file);
    pgoff_t pgoff = linear_page_index(dst_vma, dst_addr);
    struct page *page;
    int ret;

    ret = shmem_getpage(inode, pgoff, &page, SGP_NOALLOC); // [4]
    // [...]
    ret = mfill_atomic_install_pte(dst_mm, dst_pmd, dst_vma, dst_addr, // [5]
                       page, false, wp_copy);
    // [...]
    return ret;
}
```

And here's the kicker: `mfill_atomic_install_pte()` **always marks the PTE as dirty** [6], no matter the actual permissions on the shared memory.

``` c
int mfill_atomic_install_pte(struct mm_struct *dst_mm, pmd_t *dst_pmd,
                 struct vm_area_struct *dst_vma,
                 unsigned long dst_addr, struct page *page,
                 bool newly_allocated, bool wp_copy)
{
    int ret;
    pte_t _dst_pte, *dst_pte;
    
    // [...]
    _dst_pte = mk_pte(page, dst_vma->vm_page_prot);
    _dst_pte = pte_mkdirty(_dst_pte); // [6]
    
    // [...]
    set_pte_at(dst_mm, dst_addr, dst_pte, _dst_pte);
    
    // [...]
}
```

This behavior was originally meant to make userfaultfd handling more reliable, but it accidentally **introduced a vulnerability similar to the Huge Dirty COW**.

### 2.3. Race Condition

Here's a simplified race timeline showing how this issue can be exploited:

```
[Thread-1]                  [Thread-2]                  [Thread-3]
__get_user_pages
  follow_page_mask
    -> no PTE
  faultin_page
    -> faults in a new COW page with file content
  cond_resched
    -> context switch

  [...]

  follow_page_mask
    follow_trans_huge_pmd
      -> page lacks write permission
  faultin_page
    -> sets FOLL_COW flag
  cond_resched
    -> context switch

  [...]

                            SYS_madvise(MADV_DONTNEED)
                              -> zeroes out the COW PTE
                            read shmem
                              shmem_fault
                                handle_userfault

                                                 =====>

                                                        SYS_ioctl(UFFDIO_CONTINUE)
                                                          userfaultfd_continue
                                                            mcontinue_atomic_pte
                                                              shmem_getpage
                                                                -> gets target (read-only) shared memory page
                                                              mfill_atomic_install_pte
                                                                pte_mkdirty
                                                                  -> marks the PTE as dirty
                                                                set_pte_at
                                                                  -> installs the PTE

  [...]

  follow_page_mask
    follow_trans_huge_pmd
      -> bypasses can_follow_write_pmd()
      -> directly writes data to the read-only shared memory
```

### 2.4. Patch

To resolve the issue of write access being mistakenly granted to read-only mappings during COW handling, the kernel maintainers removed `FOLL_COW` entirely. That change ensures **consistent permission checks** across all code paths, eliminating race condition risks caused by inconsistent flag updates.

Also, `can_follow_write_pte()` and `can_follow_write_pmd()` got stricter: with `FOLL_FORCE` set, they now perform more thorough checks to cover edge cases.