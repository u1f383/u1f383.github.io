---
layout: post
title:  "Linux Kernel TLS Part 2"
categories: linux
---

- Part1: [Linux Kernel TLS Part 1]({% post_url 2025-01-20-linux-kernel-tls-part-1 %})
- Part2: [Linux Kernel TLS Part 2]({% post_url 2025-01-21-linux-kernel-tls-part-2 %})

This is the second part of the Linux kernel TLS introduction.

## 4. Vulnerability

### 4.2. CVE-2024-26585

This analysis is based on the kernel v6.1.77, and the commit of this vulnerability is ["tls: fix race between tx work scheduling and socket close"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e01e3934a1b2d122919f73bc6ddbe1cdafc4bbdb).

The patch for CVE-2024-26583 refactors callback functions to ensure that the TX and RX objects are not accessed after `complete()` is called. However, the developers overlooked the fact that the encryption callback schedules `&ctx->tx_work.work` to the workqueue, which may access the freed TX object, resulting in the same root cause as CVE-2024-26583.

The patch for this vulnerability reorders the scheduled work to occur before `complete()` is called.

``` diff
@@ -483,19 +482,16 @@ static void tls_encrypt_done(void *data, int err)
         // [...]
-        if (rec == first_rec)
-            ready = true;
+        if (rec == first_rec) {
+            /* Schedule the transmission */
+            if (!test_and_set_bit(BIT_TX_SCHEDULED,
+                          &ctx->tx_bitmask))
+                schedule_delayed_work(&ctx->tx_work.work, 1);
+        }
     }
 
     if (atomic_dec_and_test(&ctx->encrypt_pending))
         complete(&ctx->async_wait.completion);
-
-    if (!ready)
-        return;
-
-    /* Schedule the transmission */
-    if (!test_and_set_bit(BIT_TX_SCHEDULED, &ctx->tx_bitmask))
-        schedule_delayed_work(&ctx->tx_work.work, 1);
 }
```

### 4.3. CVE-2024-26584

This analysis is based on the kernel with commit e01e3934a1b2d122919f73bc6ddbe1cdafc4bbdb.

#### 4.3.1. Patch

The commit of this vulnerability is ["net: tls: handle backlogging of crypto requests"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8590541473188741055d27b955db0777569438e3).

Both callback functions ignore all function function calls where the parameter `err` is equal to `-EINPROGRESS`.

``` diff
@@ -196,6 +196,17 @@ static void tls_decrypt_done(void *data, int err)
     struct sock *sk;
     int aead_size;
 
+    // [...]
+    if (err == -EINPROGRESS)
+        return;

@@ -449,6 +464,9 @@ static void tls_encrypt_done(void *data, int err)
     struct sk_msg *msg_en;
     struct sock *sk;
 
+    if (err == -EINPROGRESS) /* see the comment in tls_decrypt_done() */
+        return;
```

Once the `tls_do_decryption()` and `tls_do_encryption()` functions detect that the queue is full (i.e., the return value is `-EBUSY`), they will wait for the request to complete.

``` diff
@@ -269,6 +280,10 @@ static int tls_do_decryption(struct sock *sk,
     }
 
     ret = crypto_aead_decrypt(aead_req);
+    if (ret == -EBUSY) {
+        ret = tls_decrypt_async_wait(ctx);
+        ret = ret ?: -EINPROGRESS;
+    }

@@ -553,6 +571,10 @@ static int tls_do_encryption(struct sock *sk,
     atomic_inc(&ctx->encrypt_pending);
 
     rc = crypto_aead_encrypt(aead_req);
+    if (rc == -EBUSY) {
+        rc = tls_encrypt_async_wait(ctx);
+        rc = rc ?: -EINPROGRESS;
+    }
```

#### 4.3.2. Root Cause

The `crypto_request_complete()` may be called twice if `backlog` is not a NULL ptr [1]. The additional call to `crypto_request_complete()` passes `-EINPROGRESS` as error code.

``` c
static void cryptd_queue_worker(struct work_struct *work)
{
    struct crypto_async_request *req, *backlog;
    
    // [...]
    backlog = crypto_get_backlog(&cpu_queue->queue);
    req = crypto_dequeue_request(&cpu_queue->queue);

    // [...]
    if (backlog)
        crypto_request_complete(backlog, -EINPROGRESS); // [1]
    crypto_request_complete(req, 0);
}
```

The `crypto_get_backlog()` function returns the backlog request if the `queue->backlog` is not empty.

``` c
static inline struct crypto_async_request *crypto_get_backlog(
    struct crypto_queue *queue)
{
    return queue->backlog == &queue->list ? NULL :
           container_of(queue->backlog, struct crypto_async_request, list);
}
```

A request is added to the backlog list when the `crypto_enqueue_request()` function detects that the queue is full [2] and the request includes the `CRYPTO_TFM_REQ_MAY_BACKLOG` flag [3]. Requests for TLS encryption and decryption will set this flag. Notably, the request added to the backlog list is also linked to the normal queue [4].

``` c
int crypto_enqueue_request(struct crypto_queue *queue,
               struct crypto_async_request *request)
{
    // [...]
    if (unlikely(queue->qlen >= queue->max_qlen)) { // [2]
        if (!(request->flags & CRYPTO_TFM_REQ_MAY_BACKLOG)) { // [3]
            // [...]
            goto out;
        }
        
        // [...]
        if (queue->backlog == &queue->list)
            queue->backlog = &request->list;
    }
    
    queue->qlen++;
    list_add_tail(&request->list, &queue->list); // [4]
    // [...]
}
```

If the callback function is called twice, it may lead to potential issues. For example, the callback `tls_decrypt_done()` frees the `data` parameter, which means that a second call could result in a UAF vulnerability.

``` c
static void tls_decrypt_done(void *data, int err)
{
    struct aead_request *aead_req = data;
    
    // [...]
    
    kfree(aead_req);

    // [...]
}
```

### 4.4. CVE-2024-26582

This analysis is based on the kernel with commit e01e3934a1b2d122919f73bc6ddbe1cdafc4bbdb.

#### 4.4.1. Patch

The commit of this vulnerability is ["net: tls: fix use-after-free with partial reads and async decrypt"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=32b55c5ff9103b8508c1e04bfa5a08c64e7a925f).

The condition for releasing output pages has changed. Now, the output pages are freed when zero-copy is used to read data.

``` diff
@@ -224,7 +224,7 @@ static void tls_decrypt_done(void *data, int err)

     /* Free the destination pages if skb was not decrypted inplace */
-    if (sgout != sgin) {
+    if (dctx->free_sgout) {
     // [...]

@@ -1583,6 +1583,7 @@ static int tls_decrypt_sg(struct sock *sk, struct iov_iter *out_iov,
     // [...]
+    dctx->free_sgout = !!pages;
```

#### 4.4.2. Root Cause

Each decryption context corresponds to a decryption request. Before performing decryption, the `tls_decrypt_sg()` function sets up input pages where the data originates, and output pages where the decrypted data is copied. If zero-copy is disabled, this function creates a `clear_skb` [1] to serve as the outoput pages.

``` c
static int tls_decrypt_sg(struct sock *sk, struct iov_iter *out_iov,
              struct scatterlist *out_sg,
              struct tls_decrypt_arg *darg)
{
    n_sgin = skb_nsg(skb, rxm->offset + prot->prepend_size,
             rxm->full_len - prot->prepend_size);

    if (darg->zc && /* ... */) {
        // [...]
    } else {
        darg->zc = false;
        clear_skb = tls_alloc_clrtxt_skb(sk, skb, rxm->full_len); // [1]
        n_sgout = 1 + skb_shinfo(clear_skb)->nr_frags; // 1 for AAD (Additional Authenticated Data)
    }

    n_sgin = n_sgin + 1; // 1 for AAD

    // [...]
    sgin = &dctx->sg[0]; //
    sgout = &dctx->sg[n_sgin];
    // [...]

    // Init input pages
    sg_init_table(sgin, n_sgin);
    sg_set_buf(&sgin[0], dctx->aad, prot->aad_size);
    err = skb_to_sgvec(skb, &sgin[1],
               rxm->offset + prot->prepend_size,
               rxm->full_len - prot->prepend_size);
    
    // Init output pages
    if (clear_skb) {
        sg_init_table(sgout, n_sgout);
        sg_set_buf(&sgout[0], dctx->aad, prot->aad_size);
        err = skb_to_sgvec(clear_skb, &sgout[1], prot->prepend_size,
                   data_len + prot->tail_size);
    } // [...]

    darg->skb = clear_skb ?: tls_strp_msg(ctx);
    // [...]
}
```

An illustration of the configured decryption context is provided below:

<img src="/assets/image-20250121120856408.png" alt="image-20250121120856408" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

Once the decryption is complete, the output pages, data pages owned by `clear_skb`, are released by the `tls_decrypt_done()` function [2].

``` c
static void tls_decrypt_done(void *data, int err)
{
    struct scatterlist *sgout = aead_req->dst;
    struct scatterlist *sgin = aead_req->src;
    
    // [...]
    if (sgout != sgin) {
        for_each_sg(sg_next(sgout), sg, UINT_MAX, pages) {
            if (!sg)
                break;
            put_page(sg_page(sg)); // [2]
        }
    }
    // [...]
}
```

If data is read partially [3], zero-copy will be disabled. If the request is handled asynchronously, it will be enqueued in the RX list [4] and will wait for completion [5]. Once the callback function calls `complete()`, this process is awakened up and calls `process_rx_list()` function [6] to process the decrypted packet.

``` c
int tls_sw_recvmsg(struct sock *sk,
           struct msghdr *msg,
           size_t len,
           int flags,
           int *addr_len)
{
    // [...]
    while (/* ... */) {
        if (zc_capable /* true */ && to_decrypt <= len /* [3], false */ &&
            tlm->control == TLS_RECORD_TYPE_DATA)
            darg.zc = true;
        // [...]

        if (!darg.zc) {
            struct sk_buff *skb = darg.skb;
            // [...]
            if (async) {
                // [...]
                __skb_queue_tail(&ctx->rx_list, skb); // [4]
                continue;
            }
        }
    }

recv_end:
    if (async) {
        ret = tls_decrypt_async_wait(ctx); // [5]
        // [...]
        else
            err = process_rx_list(ctx, msg, &control, 0, // [6]
                          async_copy_bytes, is_peek);
    }
}
```

The `process_rx_list()` function dequeues a packet from the RX list [7] and processes it; however, the first skb, `clear_skb`, has already been freed by the callback function `tls_decrypt_done()`.

``` c
static int process_rx_list(struct tls_sw_context_rx *ctx, /*...*/)
{
    struct sk_buff *skb = skb_peek(&ctx->rx_list); // [7]

    // [...]
}
```

By the way, it seems that zero-copy can only be disabled by partial reads, which is why the commit title includes "partial reads".

#### 4.4.3. Others

For those who feel confused while tracing how SKB fragmentation works, the following illustration may be helpful.

<img src="/assets/image-20250121122734851.png" alt="image-20250121122734851" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />


### 4.5. CVE-2024-26582

This analysis is based on the kernel with commit 41532b785e9d79636b3815a64ddf6a096647d011.

#### 4.5.1. Patch

The commit of this vulnerability is ["tls: fix use-after-free on failed backlog decryption"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=13114dc5543069f7b97991e3b79937b6da05f5b0).

This patch adds a new field, `async_done`, to the `tls_decrypt_arg` structure to indicate whether the callback has completed its work, meaning that the `complete()` has been called. During error handling, the `async_done` field is used to determine whether to release certain resources, as they may have already been freed by the callback function.

#### 4.5.2. Root Cause

This vulnerability is caused by incorrect error handling. When the decryption API `crypto_aead_decrypt()` and `crypto_aead_decrypt()` return an error, the `tls_do_decryption()` function will perform certain operations if the error value is either `-EBUSY` (queued in the backlog list) or `-EINPROGRESS` (in progress); otherwise, it simply passes the error code to the caller [1].

``` c
static int tls_do_decryption(struct sock *sk,
                 struct scatterlist *sgin,
                 struct scatterlist *sgout,
                 char *iv_recv,
                 size_t data_len,
                 struct aead_request *aead_req,
                 struct tls_decrypt_arg *darg)
{
    // [...]
    ret = crypto_aead_decrypt(aead_req);
    if (ret == -EBUSY) {
        ret = tls_decrypt_async_wait(ctx);
        ret = ret ?: -EINPROGRESS;
    }
    
    if (ret == -EINPROGRESS) {
        return 0;
    } else if (darg->async) {
        atomic_dec(&ctx->decrypt_pending);
    }

    // [...]
    return ret; // [1]
}
```

Once the caller `tls_decrypt_sg()` detects an error, it will releases all output pages.

``` c
static int tls_decrypt_sg(struct sock *sk, struct iov_iter *out_iov,
              struct scatterlist *out_sg,
              struct tls_decrypt_arg *darg)
{
    // [...]
    err = tls_do_decryption(sk, sgin, sgout, dctx->iv,
                data_len + prot->tail_size, aead_req, darg);
    if (err)
        goto exit_free_pages;

    // [...]

exit_free_pages:
    // [...]
    for (; pages > 0; pages--)
        put_page(sg_page(&sgout[pages])); // [2]

    return err;
}
```

The `tls_decrypt_async_wait()` returns the decryption result [3], which is generated by the actual decryption algorithm [4] and set by the callback function [5].

``` c
static int tls_decrypt_async_wait(struct tls_sw_context_rx *ctx)
{
    // [...]
    return ctx->async_wait.err; // [3]
}

static void cryptd_aead_crypt(/* ... */)
{
    // [...]
    err = crypt(subreq); // [4]

    // [...]
    aead_request_complete(req, err); // call `tls_decrypt_done()` internally
    
    // [...]
}

static void tls_decrypt_done(void *data, int err)
{
    // [...]
    if (err) {
        ctx->async_wait.err = err; // [5]
        // [...]
    }
    // [...]
}
```

As a result, the `tls_decrypt_async_wait()` function may also return `-EBADMSG` because the decryption alorithm failes to decrypt a malformed TLS packet. However, in this case, the output pages will be freed twice: once by the callback function `tls_decrypt_done()` [6], and again by the `tls_decrypt_sg()` function.

``` c
static void tls_decrypt_done(void *data, int err)
{
    // [...]
    if (dctx->free_sgout) {
        for_each_sg(sg_next(sgout), sg, UINT_MAX, pages) {
            if (!sg)
                break;
            put_page(sg_page(sg)); // [6]
        }
    }
    // [...]
}
```