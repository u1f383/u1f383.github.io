---
layout: post
title:  "Linux Kernel TLS Part 1"
categories: linux
---

- Part1: [Linux Kernel TLS Part 1]({% post_url 2025-01-20-linux-kernel-tls-part-1 %})

Last week, I prepared an introduction to Linux kernel TLS for my study group. You can check out the [slide](/slides/study_groups/Deephacking-20250119.pdf) for a general concept.

In this post, I will provide more details than the slide, offering a deep dive into how the Linux kernel's TLS implementation works and highlight some previously exploited vulnerabilities. Enjoy 🙂 !

## 1. Overview

Similar to other socket types, the Linux kernel's TLS implementation defines its own packet-handling operations, making it a good entry point for understanding the architecture of the subsystem.

### 1.1. Initialization

The TLS subsystem registers its ULP ops during initialization.

``` c
static struct tcp_ulp_ops tcp_tls_ulp_ops __read_mostly = {
    .name            = "tls",
    .owner           = THIS_MODULE,
    .init            = tls_init,
    .update          = tls_update,
    .get_info        = tls_get_info,
    .get_info_size   = tls_get_info_size,
};

static int __init tls_register(void)
{
    int err;

    err = register_pernet_subsys(&tls_proc_ops);
    // [...]
    
    tcp_register_ulp(&tcp_tls_ulp_ops); // <-----------
    // [...]   
}
```

A TCP socket can set its ULP by `SYS_setsockopt`. If the given ULP name is "tls", the `__tcp_ulp_find_autoload()` will return `&tcp_tls_ulp_ops` as ULP ops.

``` c
int do_tcp_setsockopt(struct sock *sk, int level, int optname,
              sockptr_t optval, unsigned int optlen)
{
    switch (optname) {
    case TCP_ULP:
        // [...]
        sockopt_lock_sock(sk);
        err = tcp_set_ulp(sk, name);
        sockopt_release_sock(sk);
        // [...]
    }
    // [...]
}

int tcp_set_ulp(struct sock *sk, const char *name)
{
    const struct tcp_ulp_ops *ulp_ops;
    ulp_ops = __tcp_ulp_find_autoload(name); // &tcp_tls_ulp_ops
    return __tcp_set_ulp(sk, ulp_ops);
}
```

The `__tcp_set_ulp()` will calls the TLS init handler to setting the socket ULP [1].

``` c
static int __tcp_set_ulp(struct sock *sk, const struct tcp_ulp_ops *ulp_ops)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    int err;

    // [...]
    err = ulp_ops->init(sk); // [1]
    icsk->icsk_ulp_ops = ulp_ops;
    return 0;
}
```

The TLS init handler updates `sock` and its proto and create a TLS context (`tls_context`) object.

``` c
static int tls_init(struct sock *sk)
{
    struct tls_context *ctx;

    // [...]
    
    ctx = tls_ctx_create(sk);
    ctx->tx_conf = TLS_BASE;
    ctx->rx_conf = TLS_BASE;
    update_sk_prot(sk, ctx);
    
    // [...]
}
```

After itialization, the TLS socket object is as follows:

<img src="/assets/image-20250113155355717.png" alt="image-20250113155355717" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

### 1.2. Set TX/RX

Once a TLS socket is created, we can further call `SYS_setsockopt` to set its `TLS_TX` and `TLS_RX`, which are crypto configurations for transmission and receive.

``` c
static int do_tls_getsockopt(struct sock *sk, int optname,
                 char __user *optval, int __user *optlen)
{
    int rc = 0;

    lock_sock(sk);

    switch (optname) {
    case TLS_TX:
    case TLS_RX:
        lock_sock(sk);
        rc = do_tls_setsockopt_conf(sk, optval, optlen, optname == TLS_TX);
        release_sock(sk);
        break;
    }
    // [...]
}
```

We focus solely on the `TLS_TX` setting here because the `TLS_RX` follows a similar process.

The `do_tls_setsockopt_conf()` function first attemps to offload TLS to hardware [1]. If it fails, this function then offloads TLS in the software level [2]. The most of network devices does not support TLS offload, so it is more frequent that the TLS is handled in the software level. Finally, it updates tx conf [3] and set the corresponding protocol ops [4].

``` c
static int do_tls_setsockopt_conf(struct sock *sk, sockptr_t optval,
                  unsigned int optlen, int tx)
{
    struct tls_context *ctx = tls_get_ctx(sk);
    
    // [...]
    if (tx) {
        rc = tls_set_device_offload(sk, ctx); // [1]
        conf = TLS_HW;
        if (!rc) {
            // [...]
        } else {
            rc = tls_set_sw_offload(sk, ctx, 1); // [2]
            // [...]
            conf = TLS_SW;
        }
    }
    // [...]
    ctx->tx_conf = conf; // [3]
    update_sk_prot(sk, ctx); // [4]

    // [...]
}
```

There are many encryption types for TLS, and you can refer variable `&tls_cipher_desc[]` for more details. The example code for setting AES_GCM_128 crypto is as follows:

``` c
struct tls12_crypto_info_aes_gcm_128 crypto_info;

memset(&crypto_info, 0, sizeof(crypto_info));
crypto_info.info.version = TLS_1_2_VERSION;
crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

memcpy(crypto_info.key, "0123456789ABCDEF", TLS_CIPHER_AES_GCM_128_KEY_SIZE); // 16
memcpy(crypto_info.iv, "12345678", TLS_CIPHER_AES_GCM_128_IV_SIZE); // 8
memcpy(crypto_info.salt, "SALT", TLS_CIPHER_AES_GCM_128_SALT_SIZE); // 4

setsockopt(sockfd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
setsockopt(sockfd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
```

<br>

The `tls_set_sw_offload()` function is used to initialized software TLS. First, it calls `init_ctx_tx()` to create a `tls_sw_context_tx` object [5]. After that, it initializes TLS protocol information [6] and the cipher context [7] with provided crypto parameters, such as IV and SALT.

``` c
int tls_set_sw_offload(struct sock *sk, struct tls_context *ctx, int tx)
{
    const struct tls_cipher_desc *cipher_desc;
    struct tls_sw_context_tx *sw_ctx_tx = NULL;
    struct tls_prot_info *prot = &tls_ctx->prot_info;
    struct cipher_context *cctx;

    ctx->priv_ctx_tx = init_ctx_tx(ctx, sk); // [5]
    cctx = &ctx->tx;

    // [6]
    prot->version = crypto_info->version;
    prot->cipher_type = crypto_info->cipher_type;
    // [...]

    // [7]
    cctx->iv = kmalloc(cipher_desc->iv + cipher_desc->salt, GFP_KERNEL);
    memcpy(cctx->iv, salt, cipher_desc->salt);
    memcpy(cctx->iv + cipher_desc->salt, iv, cipher_desc->iv);
    
    cctx->rec_seq = kmemdup(rec_seq, cipher_desc->rec_seq, GFP_KERNEL);

    if (!*aead) {
        *aead = crypto_alloc_aead(cipher_desc->cipher_name, 0, 0);
        // [...]
    }
    // [...]
}
```

After setting the software TLS, the struct relationship will look like:

<img src="/assets/image-20250113223808940.png" alt="image-20250113223808940" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

The corresponding protocol handlers are defined in the `build_protos()` function. I expand some assignment operations to make it more straightforward.

``` c
static void build_protos(struct proto prot[TLS_NUM_CONFIG][TLS_NUM_CONFIG],
             const struct proto *base)
{
    // [...]
    prot[TLS_SW][TLS_SW].setsockopt        = tls_setsockopt;
    prot[TLS_SW][TLS_SW].getsockopt        = tls_getsockopt;
    prot[TLS_SW][TLS_SW].sendmsg           = tls_sw_sendmsg;
    prot[TLS_SW][TLS_SW].recvmsg           = tls_sw_recvmsg;
    prot[TLS_SW][TLS_SW].splice_eof        = tls_sw_splice_eof;
    prot[TLS_SW][TLS_SW].sock_is_readable  = tls_sw_sock_is_readable;
    prot[TLS_SW][TLS_SW].close             = tls_sk_proto_close;
    // [...]
}
```

### 1.3. Sendmsg

The send handler of TLS sockets is `tls_sw_sendmsg()`. This function first acquires two locks: the TLS transmission lock [1] and the socket lock [2].

``` c
int tls_sw_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    struct tls_context *tls_ctx = tls_get_ctx(sk);
    int ret;

    // [...]
    ret = mutex_lock_interruptible(&tls_ctx->tx_lock); // [1]
    lock_sock(sk); // [2]
    
    ret = tls_sw_sendmsg_locked(sk, msg, size);
    
    release_sock(sk);
    mutex_unlock(&tls_ctx->tx_lock);
    return ret;
}
```

When sending packets, the kernel maintains two `skb_msg` objects (used to store packet information): one for plaintext packets and another for encrypted packets. The function `tls_sw_sendmsg_locked()` first initializes the `skb_msg` used to store encrypted packets [3] and copies data into the plaintext skb [4]. It then calls `bpf_exec_tx_verdict()` [5] to push records and attempt transmission. A "record" can be considered equivalent to a TLS packet.

``` c
static int tls_sw_sendmsg_locked(struct sock *sk, struct msghdr *msg,
                 size_t size)
{
    // [...]
    while (msg_data_left(msg)) {
        // [...]
        ret = tls_alloc_encrypted_msg(sk, required_size); // [3]

        if (/* ... */) {
            // [...]
            msg_pl = &rec->msg_plaintext;
            msg_en = &rec->msg_encrypted;

            // [...]
            ret = sk_msg_zerocopy_from_iter(sk, &msg->msg_iter, // [4]
                            msg_pl, try_to_copy);

            // [...]
            ret = bpf_exec_tx_verdict(msg_pl, sk, full_record, // [5]
                          record_type, &copied,
                          msg->msg_flags);
            
            // [...]
            continue;
        }
    }
    // [...]
}
```

The `tls_push_record()` function is called internally. It begins by copying plaintext data to the data page of the encrypted packet [6]. Next, it invokes the `tls_do_encryption()` function [7] to encrypt the packet and then calls the `tls_tx_records()` function [8] to transmit the record.

``` c
static int bpf_exec_tx_verdict(struct sk_msg *msg, struct sock *sk,
                   bool full_record, u8 record_type,
                   ssize_t *copied, int flags)
{
    // [...]
    err = tls_push_record(sk, flags, record_type); // <-----------
    // [...]
}

static int tls_push_record(struct sock *sk, int flags,
               unsigned char record_type)
{
    // [...]
    tls_fill_prepend(tls_ctx, // [6]
             page_address(sg_page(&msg_en->sg.data[i])) +
             msg_en->sg.data[i].offset,
             msg_pl->sg.size + prot->tail_size,
             record_type);
    
    // [...]
    rc = tls_do_encryption(sk, tls_ctx, ctx, req, // [7]
                   msg_pl->sg.size + prot->tail_size, i);
    
    // [...]
    tls_tx_records(sk, flags); // [8]
}
```
The `tls_tx_records()` function iterates the `ctx->tx_list`, which is the transmission packet list, and invokes `tls_push_sg()` for each packet [9]. The `tls_push_sg()` function then calls `tcp_sendmsg_locked()` [10] to transmit a TLS packet using the TCP transmission API.

``` c
int tls_tx_records(struct sock *sk, int flags)
{
    // [...]
    list_for_each_entry_safe(rec, tmp, &ctx->tx_list, list) {
        if (READ_ONCE(rec->tx_ready)) {
            // [...]
            msg_en = &rec->msg_encrypted;
            rc = tls_push_sg(sk, tls_ctx, // [9]
                     &msg_en->sg.data[msg_en->sg.curr],
                     0, tx_flags);
            // [...]
        } // [...]
    }
}

int tls_push_sg(struct sock *sk,
        struct tls_context *ctx,
        struct scatterlist *sg,
        u16 first_offset,
        int flags)
{
    struct msghdr msg = {
        .msg_flags = MSG_SPLICE_PAGES | flags,
    };
    
    // [...]
    while (1) {
        p = sg_page(sg);
        bvec_set_page(&bvec, p, size, offset);
        iov_iter_bvec(&msg.msg_iter, ITER_SOURCE, &bvec, 1, size);

        ret = tcp_sendmsg_locked(sk, &msg, size); // [10]
        // [...]
    }
}
```

### 1.4. Recvmsg

The recevie handler of TLS sockets is `tls_sw_recvmsg()`. This function first calls `process_rx_list()` to process pending decrypted records [1] and then calls `sock_rcvlowat()` to wait for a packet. Since packets can be decrypted asynchronously, the function determines whether to handle a packet asynchoronusly or not based on the packet type and the capability of rx ctx  [2].

Afterward, the `tls_rx_one_record()` function [3] is called to receive the packet. If processed asynchronously, this packet is also enqueued to `ctx->rx_list` [4]. During the next call to `tls_sw_recvmsg()`, the `process_rx_list()` will handle those enqueued packets.

``` c
int tls_sw_recvmsg(struct sock *sk,
           struct msghdr *msg,
           size_t len,
           int flags,
           int *addr_len)
{
    struct tls_context *tls_ctx = tls_get_ctx(sk);
    struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);

    // [...]
    err = process_rx_list(ctx, msg, &control, 0, len, is_peek, &rx_more); // [1]

    target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

    while (/* ... */) {
        // [...]
        tlm = tls_msg(tls_strp_msg(ctx));

        if (tlm->control == TLS_RECORD_TYPE_DATA && !bpf_strp_enabled /* true */) // [2]
            darg.async = ctx->async_capable;
        else
            darg.async = false;

        err = tls_rx_one_record(sk, msg, &darg); // [3]

        async |= darg.async;

        // [...]
        struct sk_buff *skb = darg.skb;
        
        // [...]
        if (async) {
            // [...]
            __skb_queue_tail(&ctx->rx_list, skb); // [4]
            // [...]
            continue;
        }
    }
}
```

The `tls_decrypt_sg()` function is called internally. It begins by allocating memory for an AEAD request [5] and then calls the `tls_do_decryption()` function [6] to prepare and submit the AEAD request. 

``` c
static int tls_rx_one_record(struct sock *sk, struct msghdr *msg,
                 struct tls_decrypt_arg *darg)
{
    struct tls_context *tls_ctx = tls_get_ctx(sk);
    // [...]

    err = tls_decrypt_sw(sk, tls_ctx, msg, darg); // <-----------
    // [...]
}

static int
tls_decrypt_sw(struct sock *sk, struct tls_context *tls_ctx,
           struct msghdr *msg, struct tls_decrypt_arg *darg)
{
    err = tls_decrypt_sg(sk, &msg->msg_iter, NULL, darg); // <-----------
    // [...]
}

static int tls_decrypt_sg(struct sock *sk, struct iov_iter *out_iov,
              struct scatterlist *out_sg,
              struct tls_decrypt_arg *darg)
{
    struct tls_context *tls_ctx = tls_get_ctx(sk);
    struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
    struct tls_decrypt_ctx *dctx;
    struct aead_request *aead_req;

    // [...]
    aead_size = sizeof(*aead_req) + crypto_aead_reqsize(ctx->aead_recv);
    aead_size = ALIGN(aead_size, __alignof__(*dctx));
    mem = kmalloc(aead_size + struct_size(dctx, sg, size_add(n_sgin, n_sgout)), // [5]
              sk->sk_allocation);

    aead_req = (struct aead_request *)mem;
    dctx = (struct tls_decrypt_ctx *)(mem + aead_size);
    dctx->sk = sk;
    sgin = &dctx->sg[0]; // in data segment
    sgout = &dctx->sg[n_sgin]; // out data segment

    // [...]
    err = tls_do_decryption(sk, sgin, sgout, dctx->iv, // [6]
                data_len + prot->tail_size, aead_req, darg);
    // [...]
}
```

The `tls_do_decryption()` function handles packet decryption differently depending on the value of `darg->async`. I have already reordered the function code to make it more comprehensible.

For synchronous handling, this function sets the decryption callback to `crypto_req_done()`. If the `crypto_aead_decrypt()` function returns an `-INPROGRESS` or `-BUSY` error [7], the function waits for the AEAD request to complete.

For asynchronous handling, this function sets callback to `tls_decrypt_done()` and waits for the request to complete if the error is `-EINPROGRESS` [8]. Additionally, the pending decryption count is updated both before and after submitting the request.

``` c
static int tls_do_decryption(struct sock *sk,
                 struct scatterlist *sgin,
                 struct scatterlist *sgout,
                 char *iv_recv,
                 size_t data_len,
                 struct aead_request *aead_req,
                 struct tls_decrypt_arg *darg)
{
    struct tls_context *tls_ctx = tls_get_ctx(sk);
    struct tls_prot_info *prot = &tls_ctx->prot_info;
    struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
    int ret;

    // [...]
    // ---------- synchronously ----------
    if (!darg->async) {
        // [...]
        aead_request_set_callback(aead_req,
                      CRYPTO_TFM_REQ_MAY_BACKLOG,
                      crypto_req_done, &wait);
        ret = crypto_aead_decrypt(aead_req);
        if (ret == -EINPROGRESS || ret == -EBUSY) // [7]
            ret = crypto_wait_req(ret, &wait);
        return ret;
    }

    // ---------- asynchronously ----------
    aead_request_set_callback(aead_req,
                CRYPTO_TFM_REQ_MAY_BACKLOG,
                tls_decrypt_done, aead_req);
    atomic_inc(&ctx->decrypt_pending);

    ret = crypto_aead_decrypt(aead_req);
    if (ret == -EINPROGRESS)
        return 0;

    if (ret == -EBUSY) { // [8]
        ret = tls_decrypt_async_wait(ctx);
        darg->async_done = true;
        darg->async = false;
        return ret;
    }

    atomic_dec(&ctx->decrypt_pending);
    darg->async = false;

    return ret;
}
```

### 1.5. Close

The close handler for TLS sockets is `tls_sk_proto_close()`. It first cancels the TX worker `tx_work_handler()` [1], which is responsible for transmitting encrypted records.

Next, it acquires the socket lock [2] and frees certain objects referenced by the members of TLS context object [3]. With the callback write lock held, the function restores the original TCP protocol ops [4], and releases both RX context (`tls_sw_context_rx`) and TX context (`tls_sw_context_tx`) [5].

Finally, it releases the `tls_context` object [6].

``` c
static void tls_sk_proto_close(struct sock *sk, long timeout)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tls_context *ctx = tls_get_ctx(sk);
    bool free_ctx;

    tls_sw_cancel_work_tx(ctx); // [1]

    lock_sock(sk); // [2]
    tls_sk_proto_cleanup(sk, ctx, timeo); // [3]

    // [...]
    rcu_assign_pointer(icsk->icsk_ulp_data, NULL);
    WRITE_ONCE(sk->sk_prot, ctx->sk_proto); // [4]
    // [...]
    
    release_sock(sk);
    
    // [5]
    tls_sw_free_ctx_tx(ctx);
    tls_sw_free_ctx_rx(ctx);
    ctx->sk_proto->close(sk, timeout);

    // [6]
    tls_ctx_free(sk, ctx);
}
```

## 2. Cryptography in TLS

### 2.1. Configuration

There are eight types of ciphers supported by TLS, and their descriptions are defined in the `&tls_cipher_desc[]` variable.

``` c
const struct tls_cipher_desc tls_cipher_desc[TLS_CIPHER_MAX + 1 - TLS_CIPHER_MIN] = {
    TLS_CIPHER_AES_GCM_128, ..., "gcm(aes)"
    TLS_CIPHER_AES_GCM_256, ..., "gcm(aes)"
    TLS_CIPHER_AES_CCM_128, ..., "ccm(aes)"
    TLS_CIPHER_CHACHA20_POLY1305, ..., "rfc7539(chacha20,poly1305)"
    TLS_CIPHER_SM4_GCM, ..., "gcm(sm4)"
    TLS_CIPHER_SM4_CCM, ..., "ccm(sm4)"
    TLS_CIPHER_ARIA_GCM_128, ..., "gcm(aria)"
    TLS_CIPHER_ARIA_GCM_256, ..., "gcm(aria)"
};
```

The `get_cipher_desc()` function serves as a wrapper to retrieve the description for the corresponding cipher type.

``` c
static inline const struct tls_cipher_desc *get_cipher_desc(u16 cipher_type)
{
    // [...] bound check
    return &tls_cipher_desc[cipher_type - TLS_CIPHER_MIN];
}
```

When configuring TX/RX, the `tls_set_sw_offload()` function initializes the crypto metadata based on the description, including the AEAD request object [1].

``` c
int tls_set_sw_offload(struct sock *sk, struct tls_context *ctx, int tx)
{
    struct crypto_aead **aead;
    // [...]

    cipher_desc = get_cipher_desc(crypto_info->cipher_type);
    // [...]
    iv = crypto_info_iv(crypto_info, cipher_desc);
    key = crypto_info_key(crypto_info, cipher_desc);
    salt = crypto_info_salt(crypto_info, cipher_desc);
    rec_seq = crypto_info_rec_seq(crypto_info, cipher_desc);
    // [...]
    *aead = crypto_alloc_aead(cipher_desc->cipher_name, 0, 0); // [1]
    // [...]
}
```

The `crypto_alloc_tfm_node()` function is called internally. It first gets algorithm object (`crypto_alg`) using the provided algorithm name, such as `"gcm(aes)"` or `"ccm(aes)"` [2]. It then allocates a transformation object [3] based on the algorithm object.

``` c
struct crypto_aead *crypto_alloc_aead(const char *alg_name, u32 type, u32 mask)
{
    return crypto_alloc_tfm(alg_name, &crypto_aead_type, type, mask); // <-----------
}

static inline void *crypto_alloc_tfm(const char *alg_name,
               const struct crypto_type *frontend, u32 type, u32 mask)
{
    return crypto_alloc_tfm_node(alg_name, frontend, type, mask, NUMA_NO_NODE); // <-----------
}

void *crypto_alloc_tfm_node(const char *alg_name,
               const struct crypto_type *frontend, u32 type, u32 mask,
               int node)
{
    void *tfm;
    struct crypto_alg *alg;
    
    // [...]
    alg = crypto_find_alg(alg_name, frontend, type, mask); // [2]
    
    // [...]
    tfm = crypto_create_tfm_node(alg, frontend, node); // [3]

    // [...]
    return tfm;
}
```

The `crypto_alg_mod_lookup()` is responsible for locating the targeted algorithm and returning it. First, it calls `crypto_larval_lookup()` [4] to lookup the algorithm from linked list. If the target alrorithm does not exist, its then invokes `crypto_probing_notify()` to send a `CRYPTO_MSG_ALG_REQUEST` request to Cryptomgr [5]. Finally, it waits for the probing to complete [6] and frees the `larval` object [7].

``` c
struct crypto_alg *crypto_find_alg(const char *alg_name,
                   const struct crypto_type *frontend,
                   u32 type, u32 mask)
{
    if (frontend) {
        // [...]
        // update type & mask
    }

    return crypto_alg_mod_lookup(alg_name, type, mask); // <-----------
}

struct crypto_alg *crypto_alg_mod_lookup(const char *name, u32 type, u32 mask)
{
    struct crypto_alg *alg;
    struct crypto_alg *larval;

    larval = crypto_larval_lookup(name, type, mask); // [4]
    if (/* ... */ !crypto_is_larval(larval))
        return larval;
    
    ok = crypto_probing_notify(CRYPTO_MSG_ALG_REQUEST, larval); // [5]
    if (ok == NOTIFY_STOP)
        alg = crypto_larval_wait(larval); // [6]
    
    // [...]
    crypto_larval_kill(larval); // [7]
    
    // [...]
    return alg;
}
```

#### 2.1.1. Lookup

A **larval** is essentially a temporary placeholder for a cryptographic algorithm during its initialization phase, representing an "incomplete" or "not fully ready" state. During the lookup opeartion, if the targeted algorithm doesn't exist, the newly created `larval` is linked to the `&crypto_alg_list` [1].

``` c
static struct crypto_alg *crypto_larval_lookup(const char *name, u32 type,
                           u32 mask)
{
    struct crypto_alg *alg;

    // [...]
    alg = crypto_alg_lookup(name, type, mask);

    // [...]
    else if (!alg)
        alg = crypto_larval_add(name, type, mask); // <-----------

    return alg;
}

static struct crypto_alg *crypto_larval_add(const char *name, u32 type,
                        u32 mask)
{

    struct crypto_alg *alg;
    struct crypto_larval *larval;

    larval = crypto_larval_alloc(name, type, mask);
    alg = __crypto_alg_lookup(name, type, mask);
    if (!alg) {
        alg = &larval->alg;
        list_add(&alg->cra_list, &crypto_alg_list); // [1]
    }
    return alg;
}
```

The actual lookup operation is handled by `__crypto_alg_lookup()` internally. This function iterates `&crypto_alg_list` [2] and compares algoerithm names [3]. It returns either the matching algorithm or on with a higher priortiy.

``` c
static struct crypto_alg *crypto_alg_lookup(const char *name, u32 type,
                        u32 mask)
{
    // [...]
    alg = __crypto_alg_lookup(name, (type | test) & ~fips, // <-----------
                  (mask | test) & ~fips);
    // [...]
}

static struct crypto_alg *__crypto_alg_lookup(const char *name, u32 type,
                          u32 mask)
{
    struct crypto_alg *q, *alg = NULL;
    int best = -2;

    list_for_each_entry(q, &crypto_alg_list, cra_list) { // [2]
        exact = !strcmp(q->cra_driver_name, name);
        fuzzy = !strcmp(q->cra_name, name);

        // [...]
        if (!exact && !(fuzzy && q->cra_priority > best)) // [3]
            continue;
        
        best = q->cra_priority;
        alg = q;

        if (exact)
            break;
    }

    return alg;
}
```

The following algorithms are registered during the boot process:
- `static struct akcipher_alg rsa` (rsa)
- `static struct crypto_alg null_algs[]` (cipher_null, compress_null, digest_null)
- `static struct skcipher_alg skcipher_null` (ecb(cipher_null))
- `static struct shash_alg alg` (md4)
- `static struct shash_alg alg` (md5)
- `static struct shash_alg alg` (sha1)
- `static struct shash_alg alg` (sha256)
- `static struct shash_alg alg` (sha224)
- `static struct shash_alg sha512_algs[2]` (sha512, sha384)
- `static struct shash_alg algs[]` (sha3-224, sha3-256, sha3-384, sha3-512)
- `static struct crypto_alg des_algs[2]` (des, des3_ede)
- `static struct crypto_alg aes_alg` (aes)
- `static struct skcipher_alg arc4_alg` (ecb(arc4))
- `static struct crypto_alg alg` (deflate)
- `static struct scomp_alg scomp[]` (deflate, zlib-deflate)
- `static struct shash_alg alg` (michael_mic)
- `static struct shash_alg alg` (crc32c)
- `static struct shash_alg alg` (crct10dif)
- `static struct crypto_alg alg` (lzo)
- `static struct scomp_alg scomp` (lzo)
- `static struct crypto_alg alg` (lzo-rle)
- `static struct scomp_alg scomp` (lzo-rle)
- `static struct crypto_alg alg_lz4` (lz4)
- `static struct scomp_alg scomp` (lz4)
- `static struct rng_alg rng_algs[]` (stdrng)
- `static struct shash_alg ghash_alg` (ghash)
- ...

#### 2.1.2. Probe

To probe the targeted algorithm, the kernel to dispatches a job to a kthread, and the handler is `cryptomgr_probe()` function [1].

``` c
int crypto_probing_notify(unsigned long val, void *v)
{
    int ok;

    ok = blocking_notifier_call_chain(&crypto_chain, val, v); // <-----------
    // [...]
}

int blocking_notifier_call_chain(struct blocking_notifier_head *nh,
        unsigned long val, void *v)
{
    // [...]
    ret = notifier_call_chain(&nh->head, val, v, -1, NULL); // <-----------
    // [...]
    return ret;
}

static int notifier_call_chain(struct notifier_block **nl,
                   unsigned long val, void *v,
                   int nr_to_call, int *nr_calls)
{
    while (nb && nr_to_call) {
        ret = nb->notifier_call(nb, val, v); // <----------- cryptomgr_notify()
        // [...]
        
        if (ret & NOTIFY_STOP_MASK)
            break;
    }
    return ret;
}

static int cryptomgr_notify(struct notifier_block *this, unsigned long msg,
                void *data)
{
    switch (msg) {
    case CRYPTO_MSG_ALG_REQUEST:
        return cryptomgr_schedule_probe(data); // <-----------
    // [...]
    }
}

static int cryptomgr_schedule_probe(struct crypto_larval *larval)
{
    const char *name = larval->alg.cra_name;

    // [...]
    param = kzalloc(sizeof(*param), GFP_KERNEL);
    memcpy(param->template, name, len);

    // [...]
    param->larval = larval;
    thread = kthread_run(cryptomgr_probe, param, "cryptomgr_probe"); // [1]
    
    // [...]
    return NOTIFY_STOP;
}
```

The `cryptomgr_probe()` first looks up the corresponding crypto template by its name, which is derived from the targeted algorithm name. For instance, if the algorithm name is `"gcm(aes)"`, the template name will be the substring before the left bracket, which in this case is `"gcm"`.

Next, it calls the create handler of the found crypto template to generate a new algorithm object.

``` c
static int cryptomgr_probe(void *data)
{
    struct cryptomgr_param *param = data;
    struct crypto_template *tmpl;

    tmpl = crypto_lookup_template(param->template);
    tmpl->create(tmpl, param->tb);
    
    // [...]
}
```

The crypto template objects are linked to `&crypto_template_list` [2]. A subsystem can register its templates during the booting stage by calling `crypto_register_template()` [3].

``` c
static struct crypto_template *__crypto_lookup_template(const char *name)
{
    struct crypto_template *q, *tmpl = NULL;

    // [...]
    list_for_each_entry(q, &crypto_template_list, list) { // [2]
        if (strcmp(q->name, name))
            continue;
    }
    // [...]
}

int crypto_register_template(struct crypto_template *tmpl)
{
    // [...]
    list_add(&tmpl->list, &crypto_template_list); // [3]
    // [...]
}
```

In the kernelCTF environment, the following templates are registered by default:
- `seqiv_tmpl` (seqiv)
- `echainiv_tmpl` (echainiv)
- `rsa_pkcs1pad_tmpl` (pkcs1pad)
- `crypto_cmac_tmpl` (cmac)
- `hmac_tmpl` (hmac)
- `crypto_ecb_tmpl` (ecb)
- `crypto_cbc_tmpl` (cbc)
- `crypto_cts_tmpl` (cts)
- `lrw_tmpl` (lrw)
- `xts_tmpl` (xts)
- `crypto_ctr_tmpls` (ctr, rfc3686)
- `crypto_gcm_tmpls` (gcm_base, gcm, rfc4106, rfc4543)
- `crypto_ccm_tmpls` (cbcmac, ccm_base, ccm, rfc4309)
- `cryptd_tmpl` (cryptd)
- `crypto_authenc_tmpl` (authenc)
- `crypto_authenc_esn_tmpl` (authencesn)
- `essiv_tmpl` (essiv)

We take `"gcm"` template as example. Its create handler is `crypto_gcm_create()` function. First, this function gets cipher name [4], which is the `"aes"` substring in the bracket. Then, it calls `crypto_gcm_create_common()` to do creation operation [5].

``` c
static struct crypto_template crypto_gcm_tmpls[] = {
    /* ... */ {
        .name = "gcm",
        .create = crypto_gcm_create,
        .module = THIS_MODULE,
    },
    // [...]
};

static int crypto_gcm_create(struct crypto_template *tmpl, struct rtattr **tb)
{
    const char *cipher_name;
    char ctr_name[CRYPTO_MAX_ALG_NAME];

    cipher_name = crypto_attr_alg_name(tb[1]); // [4]
    snprintf(ctr_name, CRYPTO_MAX_ALG_NAME, "ctr(%s)", cipher_name);
    return crypto_gcm_create_common(tmpl, tb, ctr_name, "ghash"); // [5]
}
```

The `crypto_gcm_create_common()` function allocates an AEAD instance object and initializes it though various complex operations. The desired crypto algorithm object is a member of this AEAD instance object and is initialized by `aead_prepare_alg()` function [6].

``` c
static int crypto_gcm_create_common(struct crypto_template *tmpl,
                    struct rtattr **tb,
                    const char *ctr_name,
                    const char *ghash_name)
{
    struct aead_instance *inst;

    inst = kzalloc(sizeof(*inst) + sizeof(*ctx), GFP_KERNEL);

    // [...]
    // initialization

    err = aead_register_instance(tmpl, inst); // <-----------
}

int aead_register_instance(struct crypto_template *tmpl,
               struct aead_instance *inst)
{
    int err;
    err = aead_prepare_alg(&inst->alg); // [6]
    return crypto_register_instance(tmpl, aead_crypto_instance(inst)); // <-----------
}
```

Finally, the `crypto_register_instance()` function is called, which links the algorithm to `&crypto_alg_list` [7] and links the instance object with the corresponding crypto template [8]. Additionally, the `crypto_alg_finish_registration()` function is called to find those `larval`s with the same algorithm names [9] and to update their `adult` field to the registerd algorithm object [10].

``` c
int crypto_register_instance(struct crypto_template *tmpl,
                 struct crypto_instance *inst)
{
    // [...]
    larval = __crypto_register_alg(&inst->alg, &algs_to_put); // <-----------
    hlist_add_head(&inst->list, &tmpl->instances); // [8]
    inst->tmpl = tmpl;
    // [...]
    return 0;
}

static struct crypto_larval *
__crypto_register_alg(struct crypto_alg *alg, struct list_head *algs_to_put)
{
    // [...]
    list_add(&alg->cra_list, &crypto_alg_list); // [7]
    
    // [...]
    crypto_alg_finish_registration(alg, true, algs_to_put);
    
    // [...]
}

static void crypto_alg_finish_registration(struct crypto_alg *alg,
                       bool fulfill_requests,
                       struct list_head *algs_to_put)
{
    list_for_each_entry(q, &crypto_alg_list, cra_list) {
        // [...]
        if (crypto_is_larval(q)) {
            struct crypto_larval *larval = (void *)q;
            // [...]

            if (strcmp(alg->cra_name, q->cra_name) && // [9]
                strcmp(alg->cra_driver_name, q->cra_name))
                continue;

            // [...]
            larval->adult = alg; // [10]

            // [...]
        }
    }
    // [...]
}
```

The hierarchy of algorithm, template, instance and spawn is shown below:

<img src="/assets/image-20250118135522529.png" alt="image-20250118135522529" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

The simplified illustration of the relationship between each structure is as follows:

<img src="/assets/image-20250116170243869.png" alt="image-20250116170243869" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

### 2.1.3. Wait

After dispatching the probing job to kthread, the kernel calls `crypto_larval_wait()` to wait for the probing process to complete. Once completion, `larval->adult` will point to the newly registered algorithm object [1].

``` c
static struct crypto_alg *crypto_larval_wait(struct crypto_alg *alg)
{
    struct crypto_larval *larval = (void *)alg;


    // [...]
    timeout = wait_for_completion_killable_timeout(
        &larval->completion, 60 * HZ);

    alg = larval->adult; // [1]

    // [...]
    return alg;
}
```

Upon returning to the caller, the `crypto_larval_kill()` function [2] is called to unlink [3] and release this temporary algorithm object [4].

``` c
struct crypto_alg *crypto_alg_mod_lookup(const char *name, u32 type, u32 mask)
{
    // [...]
    alg = crypto_larval_wait(larval);
    crypto_larval_kill(larval); // [2]
    return alg;
}

void crypto_larval_kill(struct crypto_alg *alg)
{
    struct crypto_larval *larval = (void *)alg;

    // [...]
    list_del(&alg->cra_list); // [3]

    // [...]
    crypto_alg_put(alg); // [4]
}
```

### 2.2. Encryption

When configuring TX, the `tls_set_sw_offload()` function calls `init_ctx_tx()` to create a `tls_sw_context_tx` object.

``` c
int tls_set_sw_offload(struct sock *sk, struct tls_context *ctx, int tx)
{
    // [...]
    if (tx) {
        ctx->priv_ctx_tx = init_ctx_tx(ctx, sk); // <-----------

        // [...]
    } else {
        // [...]
    }
    // [...]
}
```

This object contains several interesting fields. For example, it includes a worker object `sw_ctx_tx->tx_work` [1], whose handler is set to the `tx_work_handler()` function.

``` c
static struct tls_sw_context_tx *init_ctx_tx(struct tls_context *ctx, struct sock *sk)
{
    struct tls_sw_context_tx *sw_ctx_tx;

    sw_ctx_tx = kzalloc(sizeof(*sw_ctx_tx), GFP_KERNEL);
    crypto_init_wait(&sw_ctx_tx->async_wait);
    atomic_set(&sw_ctx_tx->encrypt_pending, 1);
    INIT_LIST_HEAD(&sw_ctx_tx->tx_list);
    INIT_DELAYED_WORK(&sw_ctx_tx->tx_work.work, tx_work_handler); // [1]
    sw_ctx_tx->tx_work.sk = sk;

    return sw_ctx_tx;
}
```

During packet transmission, the `tls_do_encryption()` function is internally invoked by `tls_sw_sendmsg()`. This function first specifies `tls_encrypt_done()` as the encryption callback [2], which runs after the encryption process is finished. It then adds the current record to `tx_list` [3], updates the pending count [4], and calls the `crypto_aead_encrypt()` API [5] exposed by the crypto subsystem.

Two specific return values require special handling: `-EBUSY` and `-EINPROGRESS`. The `-EINPROGRESS` value indicates that the encryption job is currently in progress, and the user must wait for its completion. Conversely, the `-EBUSY` value signifies that the request cannot be processed at the moment.

``` c
static int tls_do_encryption(struct sock *sk,
                 struct tls_context *tls_ctx,
                 struct tls_sw_context_tx *ctx,
                 struct aead_request *aead_req,
                 size_t data_len, u32 start)
{
    struct tls_rec *rec = ctx->open_rec;
    struct sk_msg *msg_en = &rec->msg_encrypted;
    struct scatterlist *sge = sk_msg_elem(msg_en, start);

    // [...]
    // do encryption

    aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                  tls_encrypt_done, rec); // [2]

    list_add_tail((struct list_head *)&rec->list, &ctx->tx_list); // [3]
    atomic_inc(&ctx->encrypt_pending); // [4]

    rc = crypto_aead_encrypt(aead_req); // [5]
    if (rc == -EBUSY) {
        rc = tls_encrypt_async_wait(ctx);
        rc = rc ?: -EINPROGRESS;
    }
    if (!rc || rc != -EINPROGRESS) {
        atomic_dec(&ctx->encrypt_pending);
        // [...]
    }

    if (!rc) {
        WRITE_ONCE(rec->tx_ready, true);
    } else if (rc != -EINPROGRESS) {
        list_del(&rec->list);
        return rc;
    }

    ctx->open_rec = NULL;
    // [...]
    return rc;
}
```

The `crypto_gcm_encrypt()` function serves as the handler for GCM encryption. It first invokes `crypto_skcipher_encrypt()` with the callback function `gcm_encrypt_done()` to perform symmetric encryption [6]. Then, it calls `gcm_encrypt_continue()` to generate an authentication tag [7].

``` c
int crypto_aead_encrypt(struct aead_request *req)
{
    struct crypto_aead *aead = crypto_aead_reqtfm(req);
    struct aead_alg *alg = crypto_aead_alg(aead);
    // [...]
    ret = alg->encrypt(req); // &crypto_gcm_encrypt()
    // [...]
}

static int crypto_gcm_encrypt(struct aead_request *req)
{
    struct crypto_gcm_req_priv_ctx *pctx = crypto_gcm_reqctx(req);
    struct skcipher_request *skreq = &pctx->u.skreq;
    u32 flags = aead_request_flags(req);

    // [...]
    skcipher_request_set_callback(skreq, flags, gcm_encrypt_done, req);
    return crypto_skcipher_encrypt(skreq) ?: // [6]
           gcm_encrypt_continue(req, flags); // [7]
}
```

Due to the complexity of the operation, I only provide an illustration of the execution flow here.

<img src="/assets/image-20250117170613823.png" alt="image-20250117170613823" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

If this request is dispatched to a background worker, the callback function (in this case, `tls_encrypt_done()`) is executed within the `crypto_request_complete()` function upon completion of the request.

``` c
static inline void aead_request_complete(struct aead_request *req, int err)
{
    crypto_request_complete(&req->base, err); // <-----------
}

static inline void crypto_request_complete(struct crypto_async_request *req,
                       int err)
{
    req->complete(req->data, err);
}
```

### 2.3. Decryption

When configuring RX, the `tls_set_sw_offload()` function calls `init_ctx_rx()` to create a `tls_sw_context_rx` object.

``` c
int tls_set_sw_offload(struct sock *sk, struct tls_context *ctx, int tx)
{
    // [...]
    if (tx) {
        // [...]
    } else {
        ctx->priv_ctx_rx = init_ctx_rx(ctx); // <-----------
        
        // [...]
    }
    // [...]
}

static struct tls_sw_context_rx *init_ctx_rx(struct tls_context *ctx)
{
    struct tls_sw_context_rx *sw_ctx_rx;

    sw_ctx_rx = kzalloc(sizeof(*sw_ctx_rx), GFP_KERNEL);
    crypto_init_wait(&sw_ctx_rx->async_wait);
    atomic_set(&sw_ctx_rx->decrypt_pending, 1);
    init_waitqueue_head(&sw_ctx_rx->wq);
    skb_queue_head_init(&sw_ctx_rx->rx_list);
    skb_queue_head_init(&sw_ctx_rx->async_hold);

    return sw_ctx_rx;
}
```

The `tls_do_decryption()` function is called internally during the process of receiving packets, as introduced in Section "1.4. Recvmsg." Within the `tls_do_decryption()` function, the `crypto_aead_decrypt()` API from the crypto subsystem is invoked to decrypt TLS packets.

``` c
int crypto_aead_decrypt(struct aead_request *req)
{
    struct crypto_aead *aead = crypto_aead_reqtfm(req);
    struct aead_alg *alg = crypto_aead_alg(aead);
    // [...]
    ret = alg->decrypt(req); // &crypto_gcm_decrypt
    // [...]
}
```

The execution flow of decryption is similar to that of encryption but is simpler.

``` c
static int crypto_gcm_decrypt(struct aead_request *req)
{
    struct crypto_aead *aead = crypto_aead_reqtfm(req);
    struct crypto_gcm_req_priv_ctx *pctx = crypto_gcm_reqctx(req);
    struct crypto_gcm_ghash_ctx *gctx = &pctx->ghash_ctx;
    // [...]
    gctx->complete = gcm_dec_hash_continue;
    return gcm_hash(req, flags);
}
```

### 2.3. Asynchronous

#### 2.3.1. Transmit

For transmission, the kernel determines if this encryption operation is handled asynchronously based on the return value of the `tls_do_encryption()` function. If the operation is asynchronous, it sets `ctx->async_capable` to 1 [1].

More specifically, different algorithms decide whether to create a kthread to handle requests [2]. When they choose to dispatch requests to kthead, the return value will be `-EINPROGRESS`.

``` c
static int tls_push_record(struct sock *sk, int flags,
               unsigned char record_type)
{
    // [...]
    rc = tls_do_encryption(sk, tls_ctx, ctx, req, // <-----------
                   msg_pl->sg.size + prot->tail_size, i);
    if (rc < 0) {
        // [...]
        ctx->async_capable = 1; // [1]
        return rc;
    }
    // [...]
}

static int tls_do_encryption(struct sock *sk,
                 struct tls_context *tls_ctx,
                 struct tls_sw_context_tx *ctx,
                 struct aead_request *aead_req,
                 size_t data_len, u32 start)
{
    rc = crypto_aead_encrypt(aead_req); // <-----------
    // [...]
    return rc;
}

int crypto_aead_encrypt(struct aead_request *req)
{
    struct crypto_aead *aead = crypto_aead_reqtfm(req);
    struct aead_alg *alg = crypto_aead_alg(aead);
    // [...]
    ret = alg->encrypt(req); // [2]
    return crypto_aead_errstat(istat, ret);
}
```

#### 2.3.2. Receive

For receiving, the `tls_do_decryption()` function processes packets differently if the parameter `darg->async` is set to 1 [1]. For example it assigns the function `tls_decrypt_done()` as the decryption callback [2].

The value of `darg->async` is determined in the `tls_sw_recvmsg()` function. If the `control` field in the TLS message is `TLS_RECORD_TYPE_DATA` [3], the decryption argument `darg.async` is set to asynchronous capability of the receive context [4].

``` c
int tls_sw_recvmsg(struct sock *sk,
           struct msghdr *msg,
           size_t len,
           int flags,
           int *addr_len)
{
    struct tls_context *tls_ctx = tls_get_ctx(sk);
    struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
    struct tls_msg *tlm;
    // [...]

    while (/* ... */) {
        struct tls_decrypt_arg darg;

        // [...]
        tlm = tls_msg(tls_strp_msg(ctx)); // ctx->strp.anchor
        
        // [...]
        if (tlm->control == TLS_RECORD_TYPE_DATA /* 23 */ && /* ... true */) // [3]
            darg.async = ctx->async_capable; // [4]
        else
            darg.async = false;

        err = tls_rx_one_record(sk, msg, &darg); // <-----------
        
        // [...]
    }
}

static int tls_rx_one_record(struct sock *sk, struct msghdr *msg,
                 struct tls_decrypt_arg *darg)
{
    // [...]
    err = tls_decrypt_sw(sk, tls_ctx, msg, darg); // <-----------
    if (err < 0)
        return err;
    // [...]
}

static int
tls_decrypt_sw(struct sock *sk, struct tls_context *tls_ctx,
           struct msghdr *msg, struct tls_decrypt_arg *darg)
{
    err = tls_decrypt_sg(sk, &msg->msg_iter, NULL, darg); // <-----------
    // [...]
}

static int tls_decrypt_sg(struct sock *sk, /* ... */
              struct tls_decrypt_arg *darg)
{
    // [...]
    err = tls_do_decryption(sk, sgin, sgout, dctx->iv, // <-----------
                data_len + prot->tail_size, aead_req, darg);
    // [...]
}

static int tls_do_decryption(struct sock *sk,
                 // [...]
                 struct aead_request *aead_req,
                 struct tls_decrypt_arg *darg)
{
    // [...]

    if (darg->async) { // [1]
        aead_request_set_callback(aead_req,
                      CRYPTO_TFM_REQ_MAY_BACKLOG,
                      tls_decrypt_done, aead_req);  // [2]
        atomic_inc(&ctx->decrypt_pending);
    }

    ret = crypto_aead_decrypt(aead_req);
    if (ret == -EINPROGRESS)
        return 0;

    // [...]
}
```

The async capability is configured during the RX setup. While TLS version is user-controllable [5], only algorithms with the `CRYPTO_ALG_ASYNC` flag support asynchronous operations [6].

``` c
int tls_set_sw_offload(struct sock *sk, struct tls_context *ctx, int tx)
{
    struct tls_sw_context_rx *sw_ctx_rx = NULL;
    struct crypto_tfm *tfm;

    // [...]
    else {
        sw_ctx_rx = ctx->priv_ctx_rx;
    }
    
    // [...]
    if (sw_ctx_rx) {
        tfm = crypto_aead_tfm(sw_ctx_rx->aead_recv); // &tfm->base

        // [...]
        sw_ctx_rx->async_capable =
            crypto_info->version != TLS_1_3_VERSION && // [5]
            !!(tfm->__crt_alg->cra_flags & CRYPTO_ALG_ASYNC); // [6]
    }
    // [...]
}
```

#### 2.3.3. Recon

While reading `/proc/crypto`, the kernel iterates the loaded algorithms and calls `crypto_aead_show()` function is to indicate whether an algorithm supports asynchornous operation [1]. However, sinc an algorithm can be dynamically loaded through probing, this information may not be reliable.

``` c
static void crypto_aead_show(struct seq_file *m, struct crypto_alg *alg)
{
    struct aead_alg *aead = container_of(alg, struct aead_alg, base);

    seq_printf(m, "type : aead\n");
    seq_printf(m, "async : %s\n", alg->cra_flags & CRYPTO_ALG_ASYNC ? // [1]
                   "yes" : "no");
    // [...]
}
```

Unfortunately, after reviewing the source code, I found that this flag is primarily set in vendor specific drivers, which are disabled in the kernelCTF environment.

<img src="/assets/image-20250118113417826.png" alt="image-20250118113417826" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

However, I unexpectedly discovered that some functions in the **cryptd** subsystem configure the given algorithm object with `CRYPTO_ALG_ASYNC` flag [2].

``` c
static int cryptd_create_aead(struct crypto_template *tmpl,
                      struct rtattr **tb,
                  struct crypto_attr_type *algt,
                  struct cryptd_queue *queue)
{
    struct aead_instance_ctx *ctx;
    struct aead_instance *inst;

    // [...]
    inst = kzalloc(sizeof(*inst) + sizeof(*ctx), GFP_KERNEL);
    ctx = aead_instance_ctx(inst);
    
    // [...]
    inst->alg.base.cra_flags |= CRYPTO_ALG_ASYNC | // [2]
        (alg->base.cra_flags & CRYPTO_ALG_INTERNAL);
    
    // [...]
    err = aead_register_instance(tmpl, inst);

    // [...]
}
```

What is the "cryptd" subsystem, and how can we interact with it? We will answer these questions in the next section.

## 3. Cryptd

### 3.1. Introduce

If the kernel is compiled with `CONFIG_CRYPTO_CRYPTD` option, it will start an asynchronous crypto daemon, also known as **cryptd**, which converts an arbitrary synchronous crypto algorithm into an asynchronous algorithm that runs in a kthread.

The `cryptd_tmpl` defines the create handler of cryptd template, which is the `cryptd_create()` function [1]. Besides AEAD algorithms, the `cryptd_create()` function also handles other types of algorithms.

``` c
static struct crypto_template cryptd_tmpl = {
    .name   = "cryptd",
    .create = cryptd_create, // [1]
    .module = THIS_MODULE,
};

static int cryptd_create(struct crypto_template *tmpl, struct rtattr **tb)
{
    struct crypto_attr_type *algt;

    algt = crypto_get_attr_type(tb);
    
    switch (algt->type & algt->mask & CRYPTO_ALG_TYPE_MASK) {
    case CRYPTO_ALG_TYPE_SKCIPHER:
        return cryptd_create_skcipher(tmpl, tb, algt, &queue);
    
    case CRYPTO_ALG_TYPE_HASH:
        return cryptd_create_hash(tmpl, tb, algt, &queue);
    
    case CRYPTO_ALG_TYPE_AEAD:
        return cryptd_create_aead(tmpl, tb, algt, &queue);
    }

    return -EINVAL;
}
```

As we have introduced in "2.1.2. Probe" section, the cryptomgr deals with algorithm probing requests. To load an algorithm with cryptd, we first need to find a way to ask cryptomgr to load an algorithm with an arbitrary name.

Let's quickly review the probing flow. First, a crypto API is called with an algorithm name. Then, the cryptomgr splits the algorithm name into a template name and a cipher name. For example, the algorithm name `"gcm(aes)"` is splited `"gcm"` as template name and `"aes"` as the cipher name.

Following this, the kthread `cryptomgr_probe()` is created to locate the template object based on provided name. It then calls the create handler of the template object to initialize the algorithm object.

Therefore, to create an algorithm using cryptd, the algorithm name should follow the format `"cryptd(XXXX)"`. For instance, if we create an algorithm named `"cryptd(gcm(aes))"`, the `cryptd_create_aead()` function, which is the create handler of the "cryptd" template, will be called. This function first invokes `crypto_grab_aead()` function [2] to spawn an instance of the `"gcm(aes)"` algorithm. It then registers the newly created instance in the algorithm list [3].

``` c
static int cryptd_create_aead(struct crypto_template *tmpl,
                      struct rtattr **tb,
                  struct crypto_attr_type *algt,
                  struct cryptd_queue *queue)
{
    // [...]
    err = crypto_grab_aead(&ctx->aead_spawn, aead_crypto_instance(inst), // [2]
                   crypto_attr_alg_name(tb[1]) /* gcm(aes) */, type, mask);
    
    // [...]
    err = cryptd_init_instance(aead_crypto_instance(inst), &alg->base);
    
    // [...]
    err = aead_register_instance(tmpl, inst); // [3]

    // [...]
}
```

After this process, there will be two `"gcm(aes)"` algorithm instances with different priorities in the list:
1. Created by the "gcm" template, with a priority of 100.
2. Created by the "cryptd" template, with a priority of 150 and the flag `CRYPTO_ALG_ASYNC` is set.

The reason the instance created by "cryptd" has a higher priority is that `cryptd_init_instance()` increases the original priority by 50 [4].

``` c
static int cryptd_init_instance(struct crypto_instance *inst,
                struct crypto_alg *alg)
{
    // [...]
    inst->alg.cra_priority = alg->cra_priority + 50; // [4]
    // [...]
}
```

During an algorithm lookup, the `__crypto_alg_lookup()` function returns the algorithm instance with the highest priority [5].

``` c
static struct crypto_alg *__crypto_alg_lookup(const char *name, u32 type,
                          u32 mask)
{
    list_for_each_entry(q, &crypto_alg_list, cra_list) {
        // [...]
        if (!exact && !(fuzzy && q->cra_priority > best)) // [5]
            continue;
        // [...]
    }
}
```

Now, we know the algorithm name that needs to be used, but we still have no way to call the crypto API with a controllable algorithm name.

### 3.2. Registration

The algorithm socket (`AF_ALG`) is an interface to kernel crypto API. When creating an ALG socket, the `alg_create()` function [1] is invoked. Only ALG sockets with a protocol value of 0 and a type of `SOCK_SEQPACKET` are permitted. The type ops is set to `&alg_proto_ops` [2].

``` c
static const struct net_proto_family alg_family = {
    .family   =    PF_ALG,
    .create   =    alg_create, // [1]
    .owner    =    THIS_MODULE,
};

static int alg_create(struct net *net, struct socket *sock, int protocol,
              int kern)
{
    struct sock *sk;
    
    // [..]
    sk = sk_alloc(net, PF_ALG, GFP_KERNEL, &alg_proto, kern);
    sock->ops = &alg_proto_ops; // [2]
    sock_init_data(sock, sk);
    sk->sk_destruct = alg_sock_destruct;

    return 0;
}
```

The bind handler is the `alg_bind()` function. This function retrieves algorithm type ops [3] and invokes its bind handler [4]

``` c
static const struct proto_ops alg_proto_ops = {
    .family  =    PF_ALG,
    .owner   =    THIS_MODULE,
    // [...]
    .bind    =    alg_bind,
    // [...]
};

static int alg_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    const struct af_alg_type *type;
    
    // [...]
    sa->salg_type[sizeof(sa->salg_type) - 1] = 0;
    sa->salg_name[addr_len - sizeof(*sa) - 1] = 0;
    type = alg_get_type(sa->salg_type); // [3]
    private = type->bind(sa->salg_name, sa->salg_feat, sa->salg_mask); // [4]
}
```

The `alg_get_type()` function iterates the `&alg_types` linked list [5] and returns the corresponding algorithm type object based on the provided type name.

``` c
static const struct af_alg_type *alg_get_type(const char *name)
{
    const struct af_alg_type *type = ERR_PTR(-ENOENT);
    struct alg_type_list *node;

    list_for_each_entry(node, &alg_types, list) { // [5]
        if (strcmp(node->type->name, name))
            continue;
        break;
    }
    return type;
}
```

Subsystems can call `af_alg_register_type()` to register their algorithm type objects into linked list [6].

``` c
int af_alg_register_type(const struct af_alg_type *type)
{
    struct alg_type_list *node;
    // [...]
    node = kmalloc(sizeof(*node), GFP_KERNEL);
    // [...]
    node->type = type;
    list_add(&node->list, &alg_types); // [6]
    // [...]
    return err;
}
```

The following three algorithm type objects are registered by default:
- `algif_type_hash` (hash)
- `algif_type_skcipher` (skcipher)
- `algif_type_aead` (aead)

The bind handler for "aead" algorithm is the `aead_bind()` function. Surprisely, this function calls `crypto_alloc_aead()`, the crypto probing API, using our parameters [7].

``` c
static const struct af_alg_type algif_type_aead = {
    .bind = aead_bind,
    // [...]
    .name = "aead",
    // [...]
};

static void *aead_bind(const char *name, u32 type, u32 mask)
{
    struct aead_tfm *tfm;
    struct crypto_aead *aead;
    // [...]

    tfm = kzalloc(sizeof(*tfm), GFP_KERNEL);
    aead = crypto_alloc_aead(name, type, mask); // [7]

    // [...]
    tfm->aead = aead;

    // [...]
    return tfm;
}
```

As a result, we can create an AFG socket with an arbitrary `.salg_name`, and the bind handler of the "aead" algorithm will invoke `crypto_alloc_aead()` function with this name. For example, if we set `.salg_name` to `"cryptd(gcm(aes))"`, the `"gcm(aes)"` algorithm instance will be created using the cryptd template.

``` c
#include <linux/if_alg.h>

int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
struct sockaddr_alg sa = {
    .salg_family = AF_ALG,
    .salg_type = "aead",
    .salg_name = "cryptd(gcm(aes))",
};
bind(sock, (struct sockaddr *)&sa, sizeof(sa));
```

### 3.3. Encryption

As the initialization by `cryptd_create_aead()` function, we can know that the encryption handler of the cryptd algorithm instance is the `cryptd_aead_encrypt_enqueue()` function [1].

``` c
static int cryptd_create_aead(struct crypto_template *tmpl,
                      struct rtattr **tb,
                  struct crypto_attr_type *algt,
                  struct cryptd_queue *queue)
{
    // [...]
    inst->alg.encrypt = cryptd_aead_encrypt_enqueue; // [1]
    // [...]
}
```

Encryption requests are enqueued to the CPU queue [1] and then dispatched to `cryptd_wq` workqueue [2].

``` c
static int cryptd_aead_encrypt_enqueue(struct aead_request *req)
{
    return cryptd_aead_enqueue(req, cryptd_aead_encrypt ); // <-----------
}

static int cryptd_aead_enqueue(struct aead_request *req,
                    crypto_completion_t compl)
{
    struct cryptd_aead_request_ctx *rctx = aead_request_ctx(req);
    struct crypto_aead *tfm = crypto_aead_reqtfm(req);
    struct cryptd_queue *queue = cryptd_get_queue(crypto_aead_tfm(tfm));
    
    // [...]
    // wrap the request
    return cryptd_enqueue_request(queue, &req->base); // <-----------
}

static int cryptd_enqueue_request(struct cryptd_queue *queue,
                  struct crypto_async_request *request)
{
    int err;
    struct cryptd_cpu_queue *cpu_queue;

    // [...]
    cpu_queue = this_cpu_ptr(queue->cpu_queue);
    err = crypto_enqueue_request(&cpu_queue->queue, request); // [1]

    // [...]
    queue_work_on(smp_processor_id(), cryptd_wq, &cpu_queue->work); // [2]

    // [...]
    return err;
}
```

The handler for the workqueue `cryptd_wq` is initialized to `cryptd_queue_worker()` during kernel boot.

``` c
static int cryptd_init_queue(struct cryptd_queue *queue,
                 unsigned int max_cpu_qlen /* cryptd_max_cpu_qlen, 1000 */)
{
    int cpu;
    struct cryptd_cpu_queue *cpu_queue;

    queue->cpu_queue = alloc_percpu(struct cryptd_cpu_queue);
    // [...]
    for_each_possible_cpu(cpu) {
        cpu_queue = per_cpu_ptr(queue->cpu_queue, cpu);
        crypto_init_queue(&cpu_queue->queue, max_cpu_qlen);
        INIT_WORK(&cpu_queue->work, cryptd_queue_worker); // [3]
    }
    // [...]
    return 0;
}
```

The `cryptd_queue_worker()` function dequeues a request from the CPU queue [5] and calls the complete handler [6].

``` c
static void cryptd_queue_worker(struct work_struct *work)
{
    struct cryptd_cpu_queue *cpu_queue;
    struct crypto_async_request *req, *backlog;

    cpu_queue = container_of(work, struct cryptd_cpu_queue, work);
    backlog = crypto_get_backlog(&cpu_queue->queue);
    req = crypto_dequeue_request(&cpu_queue->queue); // [5]
    
    // [...]
    crypto_request_complete(req, 0);

    if (cpu_queue->queue.qlen)
        queue_work(cryptd_wq, &cpu_queue->work);
}

static inline void crypto_request_complete(struct crypto_async_request *req,
                       int err)
{
    req->complete(req->data, err); // [6] &cryptd_aead_encrypt
}

static void cryptd_aead_encrypt(void *data, int err)
{
    struct aead_request *req = data;
    struct cryptd_aead_ctx *ctx;
    struct crypto_aead *child;

    ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
    child = ctx->child;
    cryptd_aead_crypt(req, child, err, crypto_aead_alg(child)->encrypt,
              cryptd_aead_encrypt);
}
```

The `cryptd_aead_crypt()` function invokes the actual encryption handler [7], `crypto_gcm_encrypt()`, to encrypt packets. Afterward, it calls complete callback registered in the `tls_do_encryption()` function [8].

``` c
static void cryptd_aead_crypt(struct aead_request *req,
                  struct crypto_aead *child, int err,
                  int (*crypt)(struct aead_request *req),
                  crypto_completion_t compl)
{
    // [...]
    tfm = crypto_aead_reqtfm(req);
    
    // [...]
    err = crypt(subreq); // [7] &crypto_gcm_encrypt
    
    // [...]
    aead_request_complete(req, err); 

    // [...]
}

static inline void aead_request_complete(struct aead_request *req, int err)
{
    crypto_request_complete(&req->base, err); // [8] &tls_encrypt_done
}
```

After updating the socket metadata, the `tls_encrypt_done()` function updates the ecryption pending count and wakes the up waiting process [9].

``` c
static void tls_encrypt_done(void *data, int err)
{
    struct tls_sw_context_tx *ctx;
    // [...]

    if (err == -EINPROGRESS)
        return;

    // [...]
    if (atomic_dec_and_test(&ctx->encrypt_pending))
        complete(&ctx->async_wait.completion); // [9]
    // [...]
}
```

### 3.4. Decryption

The decryption handler of the cryptd algorithm instance is the `cryptd_aead_decrypt_enqueue()` function [1], and its execution flow is the same as that of the encryption handler. Notably, encryption requests and decryption requests share the same pending queue.

``` c
static int cryptd_create_aead(struct crypto_template *tmpl,
                      struct rtattr **tb,
                  struct crypto_attr_type *algt,
                  struct cryptd_queue *queue)
{
    // [...]
    inst->alg.decrypt = cryptd_aead_decrypt_enqueue; // [1]
    // [...]
}

static int cryptd_aead_decrypt_enqueue(struct aead_request *req)
{
    return cryptd_aead_enqueue(req, cryptd_aead_decrypt );
}
```

## 4. Vulnerability

Our analysis is based on the kernel v6.6.17.

### 4.1. CVE-2024-26583

#### 4.1.1. Patch

The commit of this vulnerability is ["tls: fix race between async notify and socket close"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aec7961916f3f9e88766e2688992da6980f11b8d).

This commit removes the spinlock field from the TX and RX contexts.
``` diff
@@ -97,9 +97,6 @@ struct tls_sw_context_tx {
     // [...]
-    spinlock_t encrypt_compl_lock;
-    int async_notify;
     u8 async_capable:1;
 
@@ -136,8 +133,6 @@ struct tls_sw_context_rx {
     // [...]
-    spinlock_t decrypt_compl_lock;
```

This lock is used during encryption and decryption. For decryption, the callback function `tls_decrypt_done()` acquires the decryption lock to prevent race condition.

``` c
static void tls_decrypt_done(void *data, int err)
{
    // [...]
    spin_lock_bh(&ctx->decrypt_compl_lock);
    if (!atomic_dec_return(&ctx->decrypt_pending))
        complete(&ctx->async_wait.completion);
    spin_unlock_bh(&ctx->decrypt_compl_lock);
}
```

A similar operation can be found in the encryption callback function `tls_encrypt_done()`.

``` c
static void tls_encrypt_done(void *data, int err)
{
    // [...]
    spin_lock_bh(&ctx->encrypt_compl_lock);
    pending = atomic_dec_return(&ctx->encrypt_pending);

    if (!pending && ctx->async_notify)
        complete(&ctx->async_wait.completion);
    spin_unlock_bh(&ctx->encrypt_compl_lock);
    // [...]
}
```

#### 4.1.2. Root Cause

If the `tls_sw_recvmsg()` function transmits TLS packets asynchronously, it will first dispatch requests to the kthread. Then, it will acquire the decryption completion lock [1], retrieve the decryption pending count [2], and finally wait for the requests to complete [3].

``` c
int tls_sw_recvmsg(struct sock *sk,
           struct msghdr *msg,
           size_t len,
           int flags,
           int *addr_len)
{
    // [...]
    if (async) {
        int ret, pending;
        
        spin_lock_bh(&ctx->decrypt_compl_lock); // [1]
        reinit_completion(&ctx->async_wait.completion);
        pending = atomic_read(&ctx->decrypt_pending); // [2]
        spin_unlock_bh(&ctx->decrypt_compl_lock);
        
        ret = 0;
        if (pending)
            ret = crypto_wait_req(-EINPROGRESS, &ctx->async_wait); // <-----------
        // [...]
    }
    // [...]
}

static inline int crypto_wait_req(int err, struct crypto_wait *wait)
{
    switch (err) {
    case -EINPROGRESS:
    // [...]
        wait_for_completion(&wait->completion); // [3]
        // [...]
        break;
    }
    // [...]
}
```

The callback function `tls_decrypt_done()` is invoked after asynchornous decryption is completed. However, as soon as `complete()` is called, the waiting thread may exit and invoke the socket release handler `tls_sk_proto_close()`. Once the release handler is invoked, the RX context will be freed.

``` c
static void tls_sk_proto_close(struct sock *sk, long timeout)
{
    // [...]
    if (ctx->rx_conf == TLS_SW)
        tls_sw_free_ctx_rx(ctx);
    // [...]
}

void tls_sw_free_ctx_rx(struct tls_context *tls_ctx)
{
    struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);

    kfree(ctx); // [4]
}
```

That is, if we can extend the time window between `complete()` and `spin_unlock_bh()` in the `tls_decrypt_done()` function, it becomes possible to trigger the release handler within this time window. Consequently, the RX context object (`ctx`) used by `spin_unlock_bh()` [5] would already be freed.

``` c
static void tls_decrypt_done(void *data, int err)
{
    struct tls_sw_context_rx *ctx;
    
    // [...]
    ctx = tls_sw_ctx_rx(tls_ctx);

    // [...]
    spin_lock_bh(&ctx->decrypt_compl_lock);
    if (!atomic_dec_return(&ctx->decrypt_pending))
        complete(&ctx->async_wait.completion);

    // ============== RACE !!!! ==============

    spin_unlock_bh(&ctx->decrypt_compl_lock); // [5]
}
```

The encryption operation is also vulnerable to the same issue.

#### 4.1.3. Exploitation

I do not exploit it, but I am providing some analysis and potential exploitation paths here.

The decryption callback function, `tls_decrypt_done()`, appears unexploitable because it only performs an unlock operation.

``` c
static void tls_decrypt_done(void *data, int err)
{
    // [...]
    complete(&ctx->async_wait.completion);
    spin_unlock_bh(&ctx->decrypt_compl_lock);
}
```

However, the encryption callback function `tls_encrypt_done()` sets a bit in bitmask and schedule a work job [1], which is quite interesting.

``` c
static void tls_encrypt_done(void *data, int err)
{
    // [...]
    complete(&ctx->async_wait.completion);
    spin_unlock_bh(&ctx->encrypt_compl_lock);

    // [...]
    if (!test_and_set_bit(BIT_TX_SCHEDULED, &ctx->tx_bitmask))
        schedule_delayed_work(&ctx->tx_work.work, 1); // <-----------
}

static inline bool schedule_delayed_work(struct delayed_work *dwork,
                     unsigned long delay)
{
    return queue_delayed_work(system_wq, dwork, delay); // <-----------
}

static inline bool queue_delayed_work(struct workqueue_struct *wq,
                      struct delayed_work *dwork,
                      unsigned long delay)
{
    return queue_delayed_work_on(WORK_CPU_UNBOUND, wq, dwork, delay); // <-----------
}

bool queue_delayed_work_on(int cpu, struct workqueue_struct *wq,
               struct delayed_work *dwork, unsigned long delay)
{
    struct work_struct *work = &dwork->work; // UAF object
    
    // [...]
    if (!test_and_set_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))) {
        __queue_delayed_work(cpu, wq, dwork, delay); // [1]
        // [...]
    }
    // [...]
}
```

I manually set `dwork->work.func` to `0x4141414141414141` using GDB, and the kernel crashed!

```
[   17.407354] general protection fault: 0000 [#1] PREEMPT SMP
[   17.407936] CPU: 0 PID: 81 Comm: kworker/0:2 Not tainted 6.6.17 #16
[   17.407936] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-5 04/01/2014
[   17.407936] Workqueue: events 0x4141414141414141
[   17.407936] RIP: 0010:0x4141414141414141
[   17.407936] Code: Unable to access opcode bytes at 0x4141414141414117.
[   17.407936] RSP: 0018:ffffc9000055fe70 EFLAGS: 00000246
# [...]
[   17.407936]  <TASK>
[   17.407936]  ? die_addr+0x32/0x80
[   17.407936]  ? exc_general_protection+0x14c/0x3c0
[   17.407936]  ? asm_exc_general_protection+0x22/0x30
[   17.407936]  ? process_one_work+0x14a/0x300
[   17.407936]  ? worker_thread+0x273/0x390
```

To release the socket object, we need to return to userspace after sending the packets, but the `tls_sw_sendmsg_locked()` is blocked because the encryption pending count is not zero [2].

``` c
static int tls_sw_sendmsg_locked(struct sock *sk, struct msghdr *msg,
                 size_t size)
{
    while (msg_data_left(msg)) {
        ret = bpf_exec_tx_verdict(msg_pl, sk, full_record,
                          record_type, &copied,
                          msg->msg_flags);
        if (ret) {
            if (ret == -EINPROGRESS)
                num_async++;
            // [...]
        }
    }

    if (!num_async) {
        goto send_end;
    } else if (num_zc) {
        spin_lock_bh(&ctx->encrypt_compl_lock);
        ctx->async_notify = true;

        pending = atomic_read(&ctx->encrypt_pending);
        spin_unlock_bh(&ctx->encrypt_compl_lock);
        if (pending) // [2]
            crypto_wait_req(-EINPROGRESS, &ctx->async_wait);
        // [...]
    }
}
```

This issue can be bypassed by sending two packets, with the data address of the later packet being invalid.

``` c
static int tls_sw_sendmsg_locked(struct sock *sk, struct msghdr *msg,
                 size_t size)
{
    // [...]
    while (msg_data_left(msg)) {
        // [...]
        if (try_to_copy) {
            ret = sk_msg_memcopy_from_iter(sk, &msg->msg_iter,
                               msg_pl, try_to_copy);
            if (ret < 0)
                goto trim_sgl;
        }
        // [...]
    trim_sgl:
        // [...]
        goto send_end;
    }

send_end:
    // [...]
    return copied > 0 ? copied : ret;
}
```

The example code snippet is as follows:

``` c
#define TLS_MAX_PAYLOAD_SIZE (1 << 14)
void *buffer = mmap(NULL, TLS_MAX_PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANON | MAP_PRIVATE, -1, 0);
write(sockfd, buffer, TLS_MAX_PAYLOAD_SIZE + 1);
```

Before the TX object is released [3], the `tls_sw_release_resources_tx()` function is called to wait for the pending encryption to complete [4].

``` c
static void tls_sk_proto_close(struct sock *sk, long timeout)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tls_context *ctx = tls_get_ctx(sk);
    // [...]
    if (ctx->tx_conf != TLS_BASE /* ... */)
        tls_sk_proto_cleanup(sk, ctx, timeo); // <-----------

    // [...]
    if (ctx->tx_conf == TLS_SW)
        tls_sw_free_ctx_tx(ctx); // [3]
    
    // [...]
}

static void tls_sk_proto_cleanup(struct sock *sk,
                 struct tls_context *ctx, long timeo)
{
    // [...]
    if (ctx->tx_conf == TLS_SW) {
        // [...]
        tls_sw_release_resources_tx(sk); // <-----------
    }
    // [...]
}

void tls_sw_release_resources_tx(struct sock *sk)
{
    // [...]
    spin_lock_bh(&ctx->encrypt_compl_lock);
    ctx->async_notify = true;
    pending = atomic_read(&ctx->encrypt_pending);
    spin_unlock_bh(&ctx->encrypt_compl_lock);

    if (pending) // [4]
        crypto_wait_req(-EINPROGRESS, &ctx->async_wait);
    // [...]
}
```

The exploitation flow might be as illustrated below:

<img src="/assets/image-20250120103701332.png" alt="image-20250120103701332" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

I apply the following diff to patch the `tls_encrypt_done()` function to extend the race window for POC.

``` diff
+   mdelay(2000);
    spin_lock_bh(&ctx->encrypt_compl_lock);
    pending = atomic_dec_return(&ctx->encrypt_pending);

    if (!pending && ctx->async_notify)
        complete(&ctx->async_wait.completion);
    spin_unlock_bh(&ctx->encrypt_compl_lock);
+   mdelay(2000)
```

#### 4.1.3. Others

The relationship between request objects is a bit complex, so I have illustrated the structures and left them here for those who are interested. The `data` is the parameter of the callback functions `tls_encrypt_done()` and `tls_decrypt_done()`.

<img src="/assets/image-20250119144258876.png" alt="image-20250119144258876" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

<br>

In next post, I will explain four more vulnerabilities!
