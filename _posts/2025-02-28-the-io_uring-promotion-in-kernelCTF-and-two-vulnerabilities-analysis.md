---
layout: post
title:  "The io_uring Promotion in kernelCTF And Two Vulnerabilities Analysis"
categories: linux
---

The Linux io_uring was introduced in 2019 to enhance I/O performance. When kCTF was first launched, io_uring became an easy target due to its complexity and relatively recent integration into the kernel. Consequently, it was later disabled due to numerous vulnerabilities — until now.

On December 13, 2024, kernelCTF aimed to evaluate whether io_uring had become more secure and announced the **io_uring promotion**. As part of this initiative, io_uring was re-enabled on the LTS kernel, with kernelCTF accepting up to five submissions until February 26, 2025.

Judging by the number of submissions, io_uring now appears to be a much harder target — great to hear!

In this post, I will analyze two vulnerabilities out of the three total submissions, both of which were exploited by Billy (@st424204) — which is crazy. Enjoy! 🙂

## 1. Overview

### 1.1. Issue SQEs

The io_uring interface supports three ways to issue SQEs (Submission Queue Entries): the system call `SYS_io_uring_enter`, the SQ thread, and the WQ thread. The system call and SQ thread are almost the same, as both invoke the function `io_submit_sqes()` to handle SQEs. The only difference is that the SQ kernel thread periodically checks the submission queue and processes SQEs, whereas the system call `SYS_io_uring_enter` must be explicitly invoked by a process.

The SQ thread is disabled by default and is enabled when the flag `IORING_SETUP_SQPOLL` is provided to the system call `SYS_io_uring_setup`.

``` c
__cold int io_sq_offload_create(struct io_ring_ctx *ctx,
                struct io_uring_params *p)
{
    // [...]
    if (ctx->flags & IORING_SETUP_SQPOLL) {
        // [...]
        
        tsk = create_io_thread(io_sq_thread, sqd, NUMA_NO_NODE);
        
        // [...]
    }
    // [...]
}
```

The WQ thread is used to asynchronously handle SQEs that may block I/O. It is also disabled by default and is internally created by the function `io_queue_iowq()`. Typically, this function is called when the user sets the `REQ_F_FORCE_ASYNC` flag in an I/O request [1].

``` c
void io_req_task_submit(struct io_kiocb *req, struct io_tw_state *ts)
{
    // [...]
    else if (req->flags & REQ_F_FORCE_ASYNC) // [1]
        io_queue_iowq(req);
    // [...]
}
```

If the I/O request fails to be handled and returns the error code `-EAGAIN`, this request will also be dispatched to WQ thread [2].

``` c
static void io_queue_async(struct io_kiocb *req, int ret)
    __must_hold(&req->ctx->uring_lock)
{
    if (ret != -EAGAIN || (req->flags & REQ_F_NOWAIT)) {
        // [...]
        return;
    }

    // [...]
    switch (io_arm_poll_handler(req, 0)) {
    // [...]
    case IO_APOLL_ABORTED:
        io_kbuf_recycle(req, 0);
        io_queue_iowq(req); // [2]
        break;
    // [...]
    }

    // [...]
}
```

### 1.2. Kernel Buffer Registration

To reduce data copy overhead between user space and kernel space, io_uring supports to register memory regions as kernel buffers in advance.

The ring buffer can be register by system call `SYS_io_uring_register` with opcode `IORING_REGISTER_PBUF_RING`.

``` c
static int __io_uring_register(struct io_ring_ctx *ctx, unsigned opcode,
                   void __user *arg, unsigned nr_args)
{
    switch (opcode) {
    // [...]
    
    case IORING_REGISTER_PBUF_RING:
        // [...]

        ret = io_register_pbuf_ring(ctx, arg);
        break;
    
    // [...]
    }
}
```

If the `IOU_PBUF_RING_MMAP` flag is set in the request, the function `io_register_pbuf_ring()` calls `io_alloc_pbuf_ring()` [1] to reserve pages for the user. The user can then use mmap with a special offset to access these pages. Otherwise, `io_pin_pbuf_ring()` is called [2] to obtain a kernel-space mapping from a user-provided memory region.

After initialization, the buffer list object is added to the global xarray with a unique ID [3].

``` c
int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
    struct io_buffer_list *bl;

    // [...]
    bl = kzalloc(sizeof(*bl), GFP_KERNEL);
    
    // [...]
    if (!(reg.flags & IOU_PBUF_RING_MMAP))
        ret = io_pin_pbuf_ring(&reg, bl); // [2]
    else
        ret = io_alloc_pbuf_ring(ctx, &reg, bl); // [1]
    
    // [...]
    io_buffer_add_list(ctx, bl, reg.bgid); // [3]
    
    // [...]
}
```

The `is_mapped` field of a kernel buffer allocated by `io_register_pbuf_ring()` is set to 1, while the value of the `is_mmap` field is determined by the `IOU_PBUF_RING_MMAP` flag.

``` c
static int io_pin_pbuf_ring(struct io_uring_buf_reg *reg,
                struct io_buffer_list *bl)
{
    // [...]
    bl->is_mapped = 1;
    bl->is_mmap = 0;
    return 0;
}

static int io_alloc_pbuf_ring(struct io_ring_ctx *ctx,
                  struct io_uring_buf_reg *reg,
                  struct io_buffer_list *bl)
{
    // [...]
    bl->is_mapped = 1;
    bl->is_mmap = 1;
    return 0;
}
```

Besides `SYS_io_uring_register`, the request opcode `IORING_OP_PROVIDE_BUFFERS` is also used to register provided buffers (pbuf).

The opcode handler `io_provide_buffers()` first allocates a new buffer list [4] and adds it to the global xarray [5]. It then calls the function `io_add_buffers()` [8] to initialize the sub-buffers.

``` c
int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags)
{
    // [...]
    bl = kzalloc(sizeof(*bl), GFP_KERNEL_ACCOUNT); // [4]

    // [...]
    ret = io_buffer_add_list(ctx, bl, p->bgid); // [5]

    // [...]
    ret = io_add_buffers(ctx, p, bl); // [6]

    // [...]
}
```

Due to `kzalloc()`, both the `is_mapped` and `is_mmap` fields of the buffer list object are initialized to zero.

### 1.3. Kernel Buffer Selection

When handling an I/O request, the kernel calls `io_do_buffer_select()` to check if the `REQ_F_BUFFER_SELECT` flag is set.

``` c
static inline bool io_do_buffer_select(struct io_kiocb *req)
{
    if (!(req->flags & REQ_F_BUFFER_SELECT))
        return false;
    // [...]
}
```

If the flag is set, the kernel selects a kernel buffer based on the provided buffer ID (`buf_index`) [1] and uses the corresponding memory region to read and write data. The pbuf and ring buffer need to be handled differently, and the handler selection is based on the value of `is_mapped` [2].

``` c
void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
                  unsigned int issue_flags)
{
    struct io_ring_ctx *ctx = req->ctx;
    struct io_buffer_list *bl;
    void __user *ret = NULL;

    // [...]
    bl = io_buffer_get_list(ctx, req->buf_index); // [1]
    if (likely(bl)) {
        if (bl->is_mapped) // [2]
            ret = io_ring_buffer_select(req, len, bl, issue_flags);
        else
            ret = io_provided_buffer_select(req, len, bl);
    }
    // [...]
    return ret;
}
```

When an I/O request is completed or partially finished, the functions `io_put_kbuf()` or `io_kbuf_recycle()` are called to recycle the kernel buffer.

The `io_put_kbuf()` function internally calls `__io_put_kbuf_list()`, which updates the `head` field of the buffer list [3] if it is a ring buffer. After recycling, the buffer selection flag is cleared [4].

``` c
static inline unsigned int io_put_kbuf(struct io_kiocb *req,
                       unsigned issue_flags)
{

    if (!(req->flags & (REQ_F_BUFFER_SELECTED|REQ_F_BUFFER_RING)))
        return 0;
    return __io_put_kbuf(req, issue_flags); // <-------------
}

unsigned int __io_put_kbuf(struct io_kiocb *req, unsigned issue_flags)
{
    unsigned int cflags;
    // [...]
    if (req->flags & REQ_F_BUFFER_RING) {
        cflags = __io_put_kbuf_list(req, NULL); // <-------------
    } else if (issue_flags & IO_URING_F_UNLOCKED) {
        // [...]
        cflags = __io_put_kbuf_list(req, &ctx->io_buffers_comp); // <-------------
        // [...]
    } else {
        cflags = __io_put_kbuf_list(req, &req->ctx->io_buffers_cache); // <-------------
    }
    return cflags;
}

static inline unsigned int __io_put_kbuf_list(struct io_kiocb *req,
                          struct list_head *list)
{
    unsigned int ret = IORING_CQE_F_BUFFER | (req->buf_index << IORING_CQE_BUFFER_SHIFT);

    if (req->flags & REQ_F_BUFFER_RING) {
        if (req->buf_list) {
            req->buf_index = req->buf_list->bgid;
            req->buf_list->head++; // [3]
        }
        req->flags &= ~REQ_F_BUFFER_RING; // [4]

    } else {
        // [...]
        req->flags &= ~REQ_F_BUFFER_SELECTED; // [4]
    }

    return ret;
}
```

The `io_kbuf_recycle()` function recycles the ring buffer using `io_kbuf_recycle_ring()` [5]. If the request is marked as `REQ_F_PARTIAL_IO` [6], `io_kbuf_recycle_ring()` will also update the `head` field of the buffer list [7].

``` c
static inline void io_kbuf_recycle(struct io_kiocb *req, unsigned issue_flags)
{
    if (req->flags & REQ_F_BUFFER_SELECTED)
        io_kbuf_recycle_legacy(req, issue_flags);
    if (req->flags & REQ_F_BUFFER_RING)
        io_kbuf_recycle_ring(req); // [5]
}

static inline void io_kbuf_recycle_ring(struct io_kiocb *req)
{
    if (req->buf_list) {
        if (req->flags & REQ_F_PARTIAL_IO) { // [6]
            req->buf_list->head++; // [7]
            req->buf_list = NULL;
        } // [...]
    }
}
```

### 1.4. Vulnerable Design

The `refs` field of the buffer list serves as a reference count. Ideally, any external reference should increment this field.

``` c
struct io_buffer_list {
    // [...]
    atomic_t refs;

    __u8 is_mapped;
    __u8 is_mmap;
};
```

However, in `io_buffer_select()`, `io_buffer_get_list()` retrieves the buffer list without updating the reference count [1], and `io_ring_buffer_select()` assigns the buffer list object to the request object [2], which is a **raw assignment**.

``` c
void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
                  unsigned int issue_flags)
{
    struct io_ring_ctx *ctx = req->ctx;
    struct io_buffer_list *bl;
    void __user *ret = NULL;

    // [...]
    bl = io_buffer_get_list(ctx, req->buf_index); // [1]
    if (likely(bl)) {
        if (bl->is_mapped)
            ret = io_ring_buffer_select(req, len, bl, issue_flags);
        // [...]
    }
    // [...]
    return ret;
}

static void __user *io_ring_buffer_select(struct io_kiocb *req, size_t *len,
                      struct io_buffer_list *bl,
                      unsigned int issue_flags)
{
    // [...]
    req->buf_list = bl; // [2]
    // [...]
}
```

Even though most critical sections are protected by the io_uring context lock, **any missed lock** could result in the buffer list object being freed between assignment and use, leading to UAF.

## 2. CVE-2025-XXXXX - io_uring: fix io_req_prep_async with provided buffers

### 2.1. Root Cause

This vulnerability has three commits to fix it, but the key commit is [here](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/io_uring?h=linux-6.6.y&id=a94592ec30ff67dc36c424327f1e0a9ceeeb9bd3).

Before dispatching a request to the WQ thread, the `prep_async` handler of the corresponding opcode is called for initialization.

``` c
int io_req_prep_async(struct io_kiocb *req)
{
    const struct io_cold_def *cdef = &io_cold_defs[req->opcode];
    // [...]
    return cdef->prep_async(req);
}
```

The handlers are defined in the opcode array `io_cold_defs[]`. Here, we will focus on discussing the handler for the `IORING_OP_READV` opcode.

``` c
const struct io_cold_def io_cold_defs[] = {
    // [...]
    [IORING_OP_READV] = {
        .async_size        = sizeof(struct io_async_rw),
        .name            = "READV",
        .prep_async        = io_readv_prep_async,
        // [...]
    },
    // [...]
}
```

The function `io_readv_prep_async()` internally calls `io_buffer_select()` [1] to attach the buffer list.

``` c
int io_readv_prep_async(struct io_kiocb *req)
{
    return io_rw_prep_async(req, ITER_DEST); // <-------------
}

static inline int io_rw_prep_async(struct io_kiocb *req, int rw)
{
    struct io_async_rw *iorw = req->async_data;
    struct iovec *iov;
    int ret;

    // [...]
    ret = io_import_iovec(rw, req, &iov, &iorw->s, 0); // <-------------
    // [...]
}
static inline int io_import_iovec(int rw, struct io_kiocb *req,
                  struct iovec **iovec, struct io_rw_state *s,
                  unsigned int issue_flags)
{
    *iovec = __io_import_iovec(rw, req, s, issue_flags); // <-------------
    // [...]
}

static struct iovec *__io_import_iovec(int ddir, struct io_kiocb *req,
                       struct io_rw_state *s,
                       unsigned int issue_flags)
{
    if (opcode == IORING_OP_READ || opcode == IORING_OP_WRITE ||
        (req->flags & REQ_F_BUFFER_SELECT)) {
        if (io_do_buffer_select(req)) {
            buf = io_buffer_select(req, &sqe_len, issue_flags); // [1]
            // [...]
        }
        // [...]
    }
}
```

After the request is dispatched to the WQ thread, the `io_submit_sqes()` function returns [2], and the `SYS_io_uring_enter` handler releases the io_uring context lock [3].

``` c
SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit,
        u32, min_complete, u32, flags, const void __user *, argp,
        size_t, argsz)
{
    // [...]
    else if (to_submit) {
        ret = io_uring_add_tctx_node(ctx);
        if (unlikely(ret))
            goto out;

        mutex_lock(&ctx->uring_lock);
        ret = io_submit_sqes(ctx, to_submit); // [2]
        // [...]
        mutex_unlock(&ctx->uring_lock); // [3]
    }
}
```

Once the lock is released, we can call `SYS_io_uring_register` to free the buffer list object while holding the lock [4].

``` c
SYSCALL_DEFINE4(io_uring_register, unsigned int, fd, unsigned int, opcode,
        void __user *, arg, unsigned int, nr_args)
{
    // [...]
    mutex_lock(&ctx->uring_lock); // [4]
    ret = __io_uring_register(ctx, opcode, arg, nr_args); // <-------------
    mutex_unlock(&ctx->uring_lock);
    // [...]
}

static int __io_uring_register(struct io_ring_ctx *ctx, unsigned opcode,
                   void __user *arg, unsigned nr_args)
// [...]
{
    // [...]
    switch (opcode) {
    case IORING_UNREGISTER_PBUF_RING:
        ret = -EINVAL;
        if (!arg || nr_args != 1)
            break;
        ret = io_unregister_pbuf_ring(ctx, arg);  // <-------------
        break;
    }
}

int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
    // [...]
    bl = io_buffer_get_list(ctx, reg.bgid);
    xa_erase(&ctx->io_bl_xa, bl->bgid);
    io_put_bl(ctx, bl);
    // [...]
}
```

ince the buffer list has only a recorded reference in the global xarray, it will be freed by `kfree_rcu()` [5].

However, the request dispatched to the WQ thread also holds a reference to the buffer list object, but this reference is not recorded by the refcount.

``` c
void io_put_bl(struct io_ring_ctx *ctx, struct io_buffer_list *bl)
{
    if (atomic_dec_and_test(&bl->refs)) {
        // [...]
        kfree_rcu(bl, rcu); // [5]
    }
}
```

The `kfree_rcu_monitor()` function frees objects registered by `kfree_rcu()` every five seconds; after that, the `buf_list` field of the buffer list object will contain a dangling pointer.

What primitive does this vulnerability provide to us? The buffer list object (`struct io_buffer_list`) is 40 bytes in size. During recycling, the handler increments the `head` field (a `u16` variable) by one, which is located at offset `0x16`.

``` c
req->buf_list->head++;
```

Wow, this seems like a rather restricted primitive 😨. I have no idea how to exploit it.

### 2.2. Patch

The kernel must ensure that the selected buffer of a request is no longer accessible after unlocking the io_uring context lock. To achieve this, this patch makes the buffer be immediately recycled after asynchronous preparation.

``` diff
@@ -1791,7 +1792,9 @@ int io_req_prep_async(struct io_kiocb *req)
         if (io_alloc_async_data(req))
             return -EAGAIN;
     }
-    return cdef->prep_async(req);
+    ret = cdef->prep_async(req);
+    io_kbuf_recycle(req, 0);
+    return ret;
```

## 3. CVE-2023-52926 - io_uring/rw: split io_read() into a helper

The commit is [here](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/io_uring?h=linux-6.6.y&id=6c27fc6a783c8a77c756dd5461b15e465020d075).

This is a 1-day commit. The upstream was fixed in 2023, but the stable kernel was not patched until September 2024. The root cause is similar to the previous one.

This vulnerability is very interesting! You wouldn't think it's exploitable at first glance.

``` diff
-int io_read(struct io_kiocb *req, unsigned int issue_flags)
+static int __io_read(struct io_kiocb *req, unsigned int issue_flags)
 {
     struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
     struct io_rw_state __s, *s = &__s;
@@ -853,7 +853,18 @@ done:
     /* it's faster to check here then delegate to kfree */
     if (iovec)
         kfree(iovec);
-    return kiocb_done(req, ret, issue_flags);
+    return ret;
+}
+
+int io_read(struct io_kiocb *req, unsigned int issue_flags)
+{
+    int ret;
+
+    ret = __io_read(req, issue_flags);
+    if (ret >= 0)
+        return kiocb_done(req, ret, issue_flags);
+
+    return ret;
```

After the patch, if the return value of the read operation is less than zero, `kiocb_done()` will not be called. Let's examine what happens if we manage to call `kiocb_done()` with a negative return value.

The function `kiocb_done()` calls `io_rw_done()` [1] to invoke the completion callback function [2].

``` c
static int kiocb_done(struct io_kiocb *req, ssize_t ret,
               unsigned int issue_flags)
{
    struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
    unsigned final_ret = io_fixup_rw_res(req, ret);
    
    /* ... */
    if (ret >= 0 && (rw->kiocb.ki_complete == io_complete_rw)) {
        // [...]
    } else {
        io_rw_done(&rw->kiocb, ret); // [1]
    }
    // [...]
}

static inline void io_rw_done(struct kiocb *kiocb, ssize_t ret)
{
    switch (ret) {
    case -EIOCBQUEUED:
        break;
    case -ERESTARTSYS:
    case -ERESTARTNOINTR:
    case -ERESTARTNOHAND:
    case -ERESTART_RESTARTBLOCK:
        ret = -EINTR;
        fallthrough;
    default:
        kiocb->ki_complete(kiocb, ret); // [2]
    }
}
```

The callback handler for a read/write request is initialized in the `io_rw_init_file()` function. There are two handlers: `io_complete_rw_iopoll()` [3] and `io_complete_rw()` [4].

``` c
static int io_rw_init_file(struct io_kiocb *req, fmode_t mode)
{
    // [...]
    if (ctx->flags & IORING_SETUP_IOPOLL) {
        // [...]
        kiocb->ki_complete = io_complete_rw_iopoll; // [3]
        // [...]
    } else {
        // [...]
        kiocb->ki_complete = io_complete_rw; // [4]
    }
    // [...]
}
```

The `io_complete_rw()` function will add a new task work with the callback `io_req_rw_complete()` [5].

``` c
static void io_complete_rw(struct kiocb *kiocb, long res)
{
    struct io_rw *rw = container_of(kiocb, struct io_rw, kiocb);
    struct io_kiocb *req = cmd_to_io_kiocb(rw);

    // [...]
    req->io_task_work.func = io_req_rw_complete; // [5]
    __io_req_task_work_add(req, IOU_F_TWQ_LAZY_WAKE);
}
```

This callback invokes `io_put_kbuf()` [6] to recycle the attached kernel buffer.

``` c
void io_req_rw_complete(struct io_kiocb *req, struct io_tw_state *ts)
{
    struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
    struct kiocb *kiocb = &rw->kiocb;

    // [...]
    if (req->flags & (REQ_F_BUFFER_SELECTED|REQ_F_BUFFER_RING)) {
        unsigned issue_flags = ts->locked ? 0 : IO_URING_F_UNLOCKED;
        req->cqe.flags |= io_put_kbuf(req, issue_flags); // [6]
    }
    // [...]
}
```

By default, task works are inserted into the twork list of the current task (`struct task_struct`), and these task works are processed at the end of any system call or thread interrupt.

However, if the io_uring context is set up with the `IORING_SETUP_DEFER_TASKRUN` flag, these tasks are only handled when the user calls `SYS_io_uring_enter` with the `IORING_ENTER_GETEVENTS` flag.

Thus, we can defer the `io_req_rw_complete()` callback and trigger it after the **buffer list object has been unregistered and freed**, leading to a UAF in the buffer list, similar to the previous vulnerability.