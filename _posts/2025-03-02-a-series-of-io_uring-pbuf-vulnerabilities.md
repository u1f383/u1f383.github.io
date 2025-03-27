---
layout: post
title:  "A Series of io_uring pbuf Vulnerabilities"
categories: linux
---

In this post, we will analyze several vulnerabilities related to io_uring pbuf, all of which have been proven to be exploitable in kernelCTF or Pwn2Own.

## 1. CVE-2024-0582 - io_uring/kbuf: defer release of mapped buffer rings

The commit is [here](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=c392cbecd8eca4c53f2bf508731257d9d0a21c2d).

### 1.1. Root Cause

The pbuf is a feature of io_uring. A user can register a ring buffer via the system call `SYS_io_uring_register` with the opcode `IORING_REGISTER_PBUF_RING`. This triggers a call to `io_register_pbuf_ring()`, and if the `IOU_PBUF_RING_MMAP` flag is not set in the request, `io_alloc_pbuf_ring()` will be called [1].

``` c
int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
    // [...]
    bl = kzalloc(sizeof(*bl), GFP_KERNEL);

    // [...]
    if (!(reg.flags & IOU_PBUF_RING_MMAP))
        // [...]
    else
        ret = io_alloc_pbuf_ring(&reg, bl); // [1]
    
    // [...]
    io_buffer_add_list(ctx, bl, reg.bgid);
    
    // [...]
}
```

`io_alloc_pbuf_ring()` allocates pages as a ring buffer [2] and marks the buffer list object (`bl`) as a mmap buffer list [3].

``` c
static int io_alloc_pbuf_ring(struct io_uring_buf_reg *reg,
                  struct io_buffer_list *bl)
{
    gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP;
    size_t ring_size;
    void *ptr;

    ring_size = reg->ring_entries * sizeof(struct io_uring_buf_ring);
    ptr = (void *) __get_free_pages(gfp, get_order(ring_size)); // [2]
    bl->buf_ring = ptr;
    // [...]
    bl->is_mmap = 1; // [3]
    return 0;
}
```

An mmap buffer list can be mapped to user space via the `SYS_mmap` system call. The io_uring mmap handler, `io_uring_validate_mmap_request()`, retrieves the buffer list ID from the offset [4], locates the corresponding buffer list in the global xarray [5], and maps the reserved pages to user space [6].

``` c
static void *io_uring_validate_mmap_request(struct file *file,
                        loff_t pgoff, size_t sz)
{
    struct io_ring_ctx *ctx = file->private_data;
    loff_t offset = pgoff << PAGE_SHIFT;
    struct page *page;
    void *ptr;

    switch (offset & IORING_OFF_MMAP_MASK) {
    // [...]
    case IORING_OFF_PBUF_RING: {
        unsigned int bgid;

        bgid = (offset & ~IORING_OFF_MMAP_MASK) >> IORING_OFF_PBUF_SHIFT; // [4]
        mutex_lock(&ctx->uring_lock);
        ptr = io_pbuf_get_address(ctx, bgid);
        mutex_unlock(&ctx->uring_lock);
        break;
        }
    // [...]
    }

    // [...]
    return ptr; // [6]
}

void *io_pbuf_get_address(struct io_ring_ctx *ctx, unsigned long bgid)
{
    struct io_buffer_list *bl;

    bl = io_buffer_get_list(ctx, bgid); // [5]
    if (!bl || !bl->is_mmap)
        return NULL;

    return bl->buf_ring;
}
```

To unregister a buffer list, the user invokes the `SYS_io_uring_register` system call with the opcode `IORING_UNREGISTER_PBUF_RING`. Internally, the function `__io_remove_buffers()` is called to release the reserved pages [6].

``` c
int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
    struct io_uring_buf_reg reg;
    struct io_buffer_list *bl;

    // [...]
    bl = io_buffer_get_list(ctx, reg.bgid);

    // [...]
    __io_remove_buffers(ctx, bl, -1U); // <--------------
    
    // [...]
    return 0;
}

static int __io_remove_buffers(struct io_ring_ctx *ctx,
                   struct io_buffer_list *bl, unsigned nbufs)
{
    unsigned i = 0;

    // [...]
    if (bl->is_mapped) {
        i = bl->buf_ring->tail - bl->head;
        if (bl->is_mmap) {
            folio_put(virt_to_folio(bl->buf_ring)); // [6]
            bl->buf_ring = NULL;
            bl->is_mmap = 0;
        }
        // [...]
    }
    // [...]
}
```

The problem is clear: the mmap handler does not increment the refcount for pages or the buffer list. As a resultm the mapped memory region may point to freed pages after the buffer list is unregistered, leading to **page UAF**.

### 2.2. Patch

To address the issue, the developers introduced a linked list field in the io_uring context object (`ctx->io_buf_list`), where a new ring buffer is added during initialization [1].

``` c
static int io_alloc_pbuf_ring(struct io_ring_ctx *ctx,
                  struct io_uring_buf_reg *reg,
                  struct io_buffer_list *bl)
{
    struct io_buf_free *ibf;
    size_t ring_size;
    void *ptr;

    ring_size = reg->ring_entries * sizeof(struct io_uring_buf_ring);
    ptr = io_mem_alloc(ring_size);
    
    ibf = kmalloc(sizeof(*ibf), GFP_KERNEL_ACCOUNT);
    ibf->mem = ptr;
    hlist_add_head(&ibf->list, &ctx->io_buf_list); // [1]

    bl->buf_ring = ptr;
    // [...]
    bl->is_mmap = 1;
    // [...]
}
```

The unregistration operation no longer frees these pages.

``` c
static int __io_remove_buffers(struct io_ring_ctx *ctx,
                   struct io_buffer_list *bl, unsigned nbufs)
{
    if (bl->is_mapped) {
        // [...]
        if (bl->is_mmap) {
            bl->buf_ring = NULL;
            bl->is_mmap = 0;
        } 
        // [...]
    }
    // [...]
}
```

Freeing ring buffers [2] is deferred to the release handler of the io_uring context.

``` c
static int io_uring_release(struct inode *inode, struct file *file)
{
    struct io_ring_ctx *ctx = file->private_data;

    file->private_data = NULL;
    io_ring_ctx_wait_and_kill(ctx); // <--------------
    return 0;
}

static __cold void io_ring_ctx_wait_and_kill(struct io_ring_ctx *ctx)
{
    // [...]
    INIT_WORK(&ctx->exit_work, io_ring_exit_work); // <--------------
    queue_work(system_unbound_wq, &ctx->exit_work);
}

static __cold void io_ring_exit_work(struct work_struct *work)
{
    // [...]
    io_ring_ctx_free(ctx); // <--------------
}

static __cold void io_ring_ctx_free(struct io_ring_ctx *ctx)
{
    // [...]
    io_kbuf_mmap_list_free(ctx); // <--------------
    // [...]
}

void io_kbuf_mmap_list_free(struct io_ring_ctx *ctx)
{
    struct io_buf_free *ibf;
    struct hlist_node *tmp;

    hlist_for_each_entry_safe(ibf, tmp, &ctx->io_buf_list, list) { // [2]
        hlist_del(&ibf->list);
        io_mem_free(ibf->mem);
        kfree(ibf);
    }
}
```

### 2.3. Others

At first glance, I thought that simply closing the io_uring context would free the pages again. But later, I noticed that the `SYS_mmap` handler holds the file's refcount until the file mapping is unmapped [1].

``` c
static void remove_vma(struct vm_area_struct *vma, bool unreachable)
{
    // [...]
    if (vma->vm_file)
        fput(vma->vm_file); // [1]
    // [...]
}
```

To conclude, a shared object **without refcount protection** may lead to UAF in certain situations.

## 2. io_uring: free io_buffer_list entries via RCU

The commit is [here](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=5cf4f52e6d8aa2d3b7728f568abbf9d42a3af252). It is not a vulnerability, but it is worth discussing.

In the io_uring, almost all critial sections are protected by the context lock, which is a mutex lock.

``` c
{
    mutex_lock(&ctx->uring_lock);
    // do something ...
    mutex_unlock(&ctx->uring_lock);
}
```

However, if the pbuf register handler and the mmap handler are executed concurrently, a lockdep issue may be triggered.

```
[Thread-1]                                          [Thread-2]
                                                    mmap_read_trylock()
                                                      down_read_trylock(&mm->mmap_lock)
                                                    ...
mutex_lock(&ctx->uring_lock)
__io_uring_register()
  io_register_pbuf_ring()                             io_uring_validate_mmap_request()
    __copy_from_user()                                  mutex_lock(&ctx->uring_lock) <----------- blocking
      might_fault()
        might_lock_read(&current->mm->mmap_lock) <----------- blocking
```

The lock acquirement in `io_uring_validate_mmap_request()` prevents the buffer list **from being freed**, and **RCU** can achieve the same effect without holding a lock. Therefore, part of the patch replaces the mutex lock with an RCU lock.

``` diff
@@ -3498,9 +3498,9 @@ static void *io_uring_validate_mmap_request(struct file *file,
         unsigned int bgid;
 
         bgid = (offset & ~IORING_OFF_MMAP_MASK) >> IORING_OFF_PBUF_SHIFT;
-        mutex_lock(&ctx->uring_lock);
+        rcu_read_lock();
         ptr = io_pbuf_get_address(ctx, bgid);
-        mutex_unlock(&ctx->uring_lock);
+        rcu_read_unlock();
```

The function `io_destroy_buffers()` is patched to use `kfree_rcu()` to release the buffer list instead of `kfree()`.

``` diff
@@ -303,7 +320,7 @@ void io_destroy_buffers(struct io_ring_ctx *ctx)
     xa_for_each(&ctx->io_bl_xa, index, bl) {
         xa_erase(&ctx->io_bl_xa, bl->bgid);
         __io_remove_buffers(ctx, bl, -1U);
-        kfree(bl);
+        kfree_rcu(bl, rcu);
     }
```

## 3. CVE-2024-35880 - io_uring/kbuf: hold io_buffer_list reference over mmap

The kernel version I analyzed is lts-6.6.25, and the commit is [here](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=65938e81df2197203bda4b9a0c477e7987218d66).

After this commit, the **refcount** is introduced to buffer list object.

### 3.1. Overview

The mmap handler calls `io_pbuf_get_address()` [1] with the buffer group ID to get the `buf_ring` field of the corresponding buffer list [2]. All operations are protected under the RCU lock [3, 4].

``` c
static void *io_uring_validate_mmap_request(struct file *file,
                        loff_t pgoff, size_t sz)
{
    switch (offset & IORING_OFF_MMAP_MASK) {
    // [...]
    case IORING_OFF_PBUF_RING: {
        unsigned int bgid;

        bgid = (offset & ~IORING_OFF_MMAP_MASK) >> IORING_OFF_PBUF_SHIFT;
        rcu_read_lock(); // [3]
        ptr = io_pbuf_get_address(ctx, bgid); // [1]
        rcu_read_unlock(); // [4]
        // [...]
        break;
        }
    // [...]
    }
    return ptr;
}

void *io_pbuf_get_address(struct io_ring_ctx *ctx, unsigned long bgid)
{
    struct io_buffer_list *bl;

    bl = __io_buffer_get_list(ctx, smp_load_acquire(&ctx->io_bl), bgid);

    if (!bl || !bl->is_mmap)
        return NULL;

    // [...]
    return bl->buf_ring; // [2]
}
```

If the unregister handler is called concurrently, the `__io_remove_buffers()` will be invoked to reset buffer list object [5].

``` c
int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
    // [...]
    __io_remove_buffers(ctx, bl, -1U); // [5]
    
    if (bl->bgid >= BGID_ARRAY) {
        xa_erase(&ctx->io_bl_xa, bl->bgid);
        kfree_rcu(bl, rcu);
    }
}
```

The `__io_remove_buffers()` function initializes the `buf_list` field [6], which is used as a linked list for IO buffers.

``` c
static int __io_remove_buffers(struct io_ring_ctx *ctx,
                   struct io_buffer_list *bl, unsigned nbufs)
{
    unsigned i = 0;

    // [...]
    if (bl->is_buf_ring) {
        // [...]
        INIT_LIST_HEAD(&bl->buf_list); // [6]
        return i;
    }
}
```

This field is a union with the fields `buf_pages` and `buf_ring`.

``` c
struct io_buffer_list {
    // [...]
    union {
        struct list_head buf_list;
        struct {
            struct page **buf_pages;
            struct io_uring_buf_ring *buf_ring;
        };
        // [...]
    }
    // [...]
};
```

### 3.2. Root Cause

The RCU lock only ensures that the object **is not freed** while the read lock is held, but it cannot prevent race conditions during **object updates**.

A race condition that may lead to type confusion is as follows:

```
[Thread-1]                                                  [Thread-2]
io_uring_validate_mmap_request()
  io_pbuf_get_address()
    bl = __io_buffer_get_list()
    check bl->is_mmap == 1

    (timer events ....)

                                                            io_unregister_pbuf_ring()
                                                              __io_remove_buffers()
                                                                bl = io_buffer_get_list()
                                                                bl->is_mmap = 0
                                                                INIT_LIST_HEAD(&bl->buf_list)

    return bl->buf_ring (which is overlapped with bl->buf_list.prev)
```

Consequently, the user space will share a memory region, whose address is `&bl->buf_list & ~0xfff`, with the kernel.

### 3.3. Exploitation

I apply the following patch to make winning the race condition easier.

``` diff
--- a/io_uring/kbuf_orig.c
+++ b/io_uring/kbuf.c
@@ -7,6 +7,7 @@
 #include <linux/slab.h>
 #include <linux/namei.h>
 #include <linux/poll.h>
+#include <linux/delay.h>
 #include <linux/io_uring.h>
 
 #include <uapi/linux/io_uring.h>
@@ -729,6 +730,7 @@ int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
        if (!bl->is_mapped)
                return -EINVAL;
 
+       mdelay(500);
        __io_remove_buffers(ctx, bl, -1U);
        if (bl->bgid >= BGID_ARRAY) {
                xa_erase(&ctx->io_bl_xa, bl->bgid);
@@ -737,6 +739,7 @@ int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
        return 0;
 }
 
+static int count = 0;
 void *io_pbuf_get_address(struct io_ring_ctx *ctx, unsigned long bgid)
 {
        struct io_buffer_list *bl;
@@ -753,6 +756,8 @@ void *io_pbuf_get_address(struct io_ring_ctx *ctx, unsigned long bgid)
        if (!smp_load_acquire(&bl->is_ready))
                return NULL;
 
+       if (count++ % 2 == 1)
+               mdelay(2000);
        return bl->buf_ring;
 }
```

The reason we need the `count` variable is that the mmap handler is called twice during mapping, and the exploitation succeeds only if the race condition occurs during the second call.

After mapping the buffer list, we gain **full control over the same page**, and it is a very powerful primitive!

``` bash
user@lts-6:/$ /mnt/iouring-exp
0000 0000010000014000 0000000000000000
0010 0000000000000000 0000000000000003
0020 0000000000000000 0000000000000002
0030 0000000000000000 0000000000000000
0040 0000000000000000 0000000000000000
0050 ffff888104c6e050 ffff888104c6e050
0060 0000000000000000 0000000000000000
0070 0000002000000000 ffff888104b34740
...
```

More interestingly, in that kernel version, io_uring supports static buffer lists. These lists are initialized using `io_init_bl_list()` when a buffer list with an ID less than `BGID_ARRAY` (64) [1] is registered for the first time [2].

``` c
int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
    // [...]
    if (unlikely(reg.bgid < BGID_ARRAY /* [1] */ && !ctx->io_bl /* [2] */)) {
        int ret = io_init_bl_list(ctx);
    }
    // [...]
}

static __cold int io_init_bl_list(struct io_ring_ctx *ctx)
{
    struct io_buffer_list *bl;
    int i;

    bl = kcalloc(BGID_ARRAY, sizeof(struct io_buffer_list), GFP_KERNEL);

    for (i = 0; i < BGID_ARRAY; i++) {
        INIT_LIST_HEAD(&bl[i].buf_list);
        bl[i].bgid = i;
    }
    // [...]
    return 0;
}
```

If we map a buffer list with an ID less than `BGID_ARRAY` during exploitation, `__io_buffer_get_list()` simply retrieves it from the static buffer [3, 4].

``` c
void *io_pbuf_get_address(struct io_ring_ctx *ctx, unsigned long bgid)
{
    struct io_buffer_list *bl;

    bl = __io_buffer_get_list(ctx, smp_load_acquire(&ctx->io_bl), bgid); // [3]
    // [...]
}

static struct io_buffer_list *__io_buffer_get_list(struct io_ring_ctx *ctx,
                           struct io_buffer_list *bl,
                           unsigned int bgid)
{
    if (bl && bgid < BGID_ARRAY)
        return &bl[bgid]; // [4]
    // [...]
}
```

The output of leaked static buffer lists looks as follows:

``` bash
...
0810 0000000000000000 0000000000000000
0820 ffff888104c6e820 ffff888104c6e820
0830 0000000100000001 0000000100000000
0840 ffff888104c6e840 ffff888104c6e840
0850 0000000000000002 0000000000000000
0860 ffff888104c6e860 ffff888104c6e860
0870 0000000000000003 0000000000000000
0880 ffff888104c6e880 ffff888104c6e880
0890 0000000000000004 0000000000000000
08a0 ffff888104c6e8a0 ffff888104c6e8a0
08b0 0000000000000005 0000000000000000
08c0 ffff888104c6e8c0 ffff888104c6e8c0
08d0 0000000000000006 0000000000000000
08e0 ffff888104c6e8e0 ffff888104c6e8e0
...
```

Thus, we can **control all static buffer lists** and achieve **arbitrary read and write access** by overwriting the `buf_ring` field of other buffer lists - awesome!

After that, I scan the entire heap to leak kernel text and overwrite kernel data. The full exploitation can be found [here](/assets/cve-2024-35880-poc.c).

This bug was found by Billy (@st424204), and I asked him for some details. Many thanks to him!

## 4. CVE-2025-21836 - io_uring/kbuf: reallocate buf lists on upgrade

The commit is [here](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=8802766324e1f5d414a81ac43365c20142e85603), and it was also reported by me 😄.

A provided buffer can be registered using the opcode `IORING_OP_PROVIDE_BUFFERS`. During initialization, this type of buffer list creates sub-IO buffers to `&bl->buf_list` using `io_add_buffers()` [1, 2].

``` c
int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
    struct io_ring_ctx *ctx = req->ctx;
    struct io_buffer_list *bl;
    int ret = 0;

    // [...]
    bl = kzalloc(sizeof(*bl), GFP_KERNEL_ACCOUNT);
    INIT_LIST_HEAD(&bl->buf_list);
    ret = io_buffer_add_list(ctx, bl, p->bgid);
    ret = io_add_buffers(ctx, p, bl); // [1]
    // [...]
}

static int io_add_buffers(struct io_ring_ctx *ctx, struct io_provide_buf *pbuf,
              struct io_buffer_list *bl)
{
    struct io_buffer *buf;
    u64 addr = pbuf->addr;
    int i, bid = pbuf->bid;

    for (i = 0; i < pbuf->nbufs; i++) {
        // [...]
        buf = list_first_entry(&ctx->io_buffers_cache, struct io_buffer,
                    list);
        list_move_tail(&buf->list, &bl->buf_list); // [2]
        // [...]
    }
}
```

Once it becomes empty [3], it can be converted into a **ring buffer** via the registration opcode `IORING_REGISTER_PBUF_RING`.

``` c
int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
    struct io_uring_buf_reg reg;
    struct io_buffer_list *bl, *free_bl = NULL;
    int ret;

    // [...]
    bl = io_buffer_get_list(ctx, reg.bgid);
    if (bl) {
        if (bl->is_mapped || !list_empty(&bl->buf_list) /* [3] */)
            return -EEXIST;
    }

    ret = io_alloc_pbuf_ring(ctx, &reg, bl);

    // [...]
    io_buffer_add_list(ctx, bl, reg.bgid);
    
    // [...]
}
```

However, during this conversion, the io_uring mmap handler might be called concurrently to map the provided ring buffer to user space, leading to an **incorrect update of the reference count** in the following execution sequence:

```
[thread-1]                                     [thread-2]  
io_uring_validate_mmap_request                 io_register_pbuf_ring  
  io_pbuf_get_bl                                 io_alloc_pbuf_ring  
                                                   bl->is_mmap = 1
    check if bl->is_mmap == 1  
    bl->refs += 1 (1 -> 2)                       io_buffer_add_list
                                                   bl->refs = 1 (2 -> 1)
  io_put_bl
    bl->refs -= 1 (1 -> 0)
```

After that, the buffer list remains accessible through the buffer_list xarray, but it has already been freed because its reference count is 0, leading to an UAF in the buffer list object (`struct io_buffer_list`).
