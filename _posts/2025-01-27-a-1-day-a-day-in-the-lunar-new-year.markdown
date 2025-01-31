---
layout: post
title:  "A 1-day a Day in the Lunar New Year"
categories: linux
---

農曆過年的連假期間，為了不讓腦袋停止運作，我提出了一個挑戰：每天都分析一個 Linux kernel 的漏洞 commit，六日會額外多分析一個。這些分析都不用很深入，只需要了解漏洞成因，以及猜測哪些情境下會觸發該漏洞即可。

## Day1 (1/27) net: avoid race between device unregistration and ethnl ops
> [Commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=12e070eb6964b341b41677fd260af5a305316a1f)

從 diff 可以得知該 patch 改變了找不到 network device (`-ENODEV`) 的檢查邏輯：

``` diff
@@ -90,7 +90,7 @@ int ethnl_ops_begin(struct net_device *dev)
         pm_runtime_get_sync(dev->dev.parent);
 
     if (!netif_device_present(dev) ||
-        dev->reg_state == NETREG_UNREGISTERING) {
+        dev->reg_state >= NETREG_UNREGISTERING) {
         ret = -ENODEV;
         goto err;
     }
```

`struct net_device` 的成員 `reg_state` 代表 device 目前的狀態，而大於 `NETREG_UNREGISTERING` 共有三個。

``` c
struct net_device {
    // [...]
    enum { NETREG_UNINITIALIZED=0,
            NETREG_REGISTERED,    /* completed register_netdevice */
            NETREG_UNREGISTERING,    /* called unregister_netdevice */

            // ==========================
            NETREG_UNREGISTERED,    /* completed unregister todo */
            NETREG_RELEASED,        /* called free_netdev */
            NETREG_DUMMY,        /* dummy device for NAPI poll */
    } reg_state:8;
    // [...]
}
```

觸發 panic 的執行路徑為：
```
__sys_sendto()
=> ...
==> netlink_unicast()
===> genl_rcv()
====> netlink_rcv_skb()
=====> genl_rcv_msg()
======> genl_family_rcv_msg_doit()
=======> ethnl_default_set_doit() (ops->doit)
```

`ethnl_default_set_doit()` 會呼叫 `ethnl_ops_begin()` 檢查 device 狀態 [1]，如果通過檢查則會繼續執行 `set` operation，也就是 `ethnl_set_channels()` [2]。

``` c
const struct ethnl_request_ops ethnl_channels_request_ops = {
    // [...]
    .set = ethnl_set_channels, // <---------------
    // [...]
};

static int ethnl_default_set_doit(struct sk_buff *skb, struct genl_info *info)
{
    rtnl_lock();
    ret = ethnl_ops_begin(req_info.dev); // [1]
    if (ret < 0)
        goto out_rtnl;
    
    // [...]
    ret = ops->set(&req_info, info); // [2], &ethnl_set_channels
    
    // [...]
out_rtnl:
    rtnl_unlock();
    // [...]
}
```

而 commit 敘述中提到的另一個 function `unregister_netdevice_many_notify()`，會在 hold RTNL (Routing Netlink) lock 的情況下被呼叫，把要取消註冊的 device 先 mark 成 `NETREG_UNREGISTERING` [3]。

``` c
void unregister_netdevice_many_notify(struct list_head *head,
                      u32 portid, const struct nlmsghdr *nlh)
{
    ASSERT_RTNL();
    // [...]
    list_for_each_entry(dev, head, unreg_list) {
        write_lock(&dev_base_lock);
        unlist_netdevice(dev, false);
        dev->reg_state = NETREG_UNREGISTERING; // [3]
        write_unlock(&dev_base_lock);
    }
    // [...]
}
```

在 unlock RTNL lock 時，底層會呼叫 `netdev_run_todo()` 將裝置的狀態改成 `NETREG_UNREGISTERED` [4]，之後在將 device 與其成員給釋放掉 [5]。

``` c
void rtnl_unlock(void)
{
    // [...]
    netdev_run_todo();
}

void netdev_run_todo(void)
{
    struct net_device *dev, *tmp;

    // [...]
    __rtnl_unlock();

    // [...]
    list_for_each_entry_safe(dev, tmp, &list, todo_list) {
        // [...]
        write_lock(&dev_base_lock);
        dev->reg_state = NETREG_UNREGISTERED; // [4]
        write_unlock(&dev_base_lock);
        // [...]
    }

    while (!list_empty(&list)) {
        // [...]
        dev = netdev_wait_allrefs_any(&list);
        list_del(&dev->todo_list);

        // [...]
        if (dev->priv_destructor)
            dev->priv_destructor(dev); // [5]
        if (dev->needs_free_netdev)
            free_netdev(dev); // [5]
        // [...]
    }
}
```

在刪除 device 時，`rtnetlink_rcv_msg()` 會先 hold RTNL lock [6]，而後呼叫 `rtnl_delete_link()` 來釋放不同的 device，最後呼叫 `unregister_netdevice_many_notify()` 取消註冊 device [7]。

``` c
static int rtnetlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
                 struct netlink_ext_ack *extack)
{
    // [...]
    rtnl_lock(); // [6]
    link = rtnl_get_link(family, type);
    if (link && link->doit) // &rtnl_dellink --> rtnl_delete_link()
        err = link->doit(skb, nlh, extack);
    rtnl_unlock();
    // [...]
}

int rtnl_delete_link(struct net_device *dev, u32 portid, const struct nlmsghdr *nlh)
{
    const struct rtnl_link_ops *ops;
    LIST_HEAD(list_kill);

    ops = dev->rtnl_link_ops;
    ops->dellink(dev, &list_kill);
    unregister_netdevice_many_notify(&list_kill, portid, nlh); // [7]

    return 0;
}
```

更詳細一點的 backtrace 如下：
```
__sys_sendmsg()
=> ...
==> netlink_unicast()
===> netlink_unicast_kernel()
====> netlink_rcv_skb()
=====> rtnetlink_rcv_msg()
======> rtnl_dellink()
=======> rtnl_delete_link()
```

可以想像到，觸發漏洞的執行流程應該會如下圖所示：

<img src="/assets/image-20250128010841476.png" alt="image-20250128010841476" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

## Day2 (1/28) ksmbd: fix Out-of-Bounds Write in ksmbd_vfs_stream_write
> [Commit](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=313dab082289e460391c82d855430ec8a28ddf81)

Patch 新增了 `smb2_write()` 內的變數 `offset` 不能小於 0 的檢查：

``` diff
@@ -6882,6 +6882,8 @@ int smb2_write(struct ksmbd_work *work)
     }
 
     offset = le64_to_cpu(req->Offset);
+    if (offset < 0)
+        return -EINVAL;
```

Function `smb2_write()` 是 ksmbd (Kernel SMB Daemon，也就是 In-kernel SMB Server) 用來處理寫入請求 (`SMB2_WRITE_HE`) 的 handler。該 function 會使用請求的 `Offset` [1] 與 `Length` [2] 欄位作為存取檔案的偏移與資料量，傳入 `ksmbd_vfs_write()` [3] 來完成寫入操作。

``` c
typedef long long __kernel_loff_t;
typedef __kernel_loff_t loff_t;

int smb2_write(struct ksmbd_work *work)
{
    loff_t offset;
    size_t length;
    // [...]
    offset = le64_to_cpu(req->Offset); // [1]
    length = le32_to_cpu(req->Length); // [2]

    if (is_rdma_channel == false) {
        // [...]
        data_buf = (char *)(((char *)&req->hdr.ProtocolId) +
                    le16_to_cpu(req->DataOffset));
        // [...]
        err = ksmbd_vfs_write(work, fp, data_buf, length, &offset, // [3]
                      writethrough, &nbytes);
    }
    // [...]
}
```

當目標檔案是 stream 類型時 [4]，`ksmbd_vfs_write()` 會再呼叫 `ksmbd_vfs_stream_write()` [5]，而傳入的參數 `pos` 為我們可控成負數值的 offset。

``` c
static inline bool ksmbd_stream_fd(struct ksmbd_file *fp)
{
    return fp->stream.name != NULL;
}

int ksmbd_vfs_write(struct ksmbd_work *work, struct ksmbd_file *fp,
            char *buf, size_t count, loff_t *pos, bool sync,
            ssize_t *written)
{
    // [...]
    loff_t offset = *pos;
    int err = 0;
    // [...]

    if (ksmbd_stream_fd(fp)) { // [4]
        err = ksmbd_vfs_stream_write(fp, buf, pos, count); // [5]
        // [...]
    }
}
```

如果 stream file 沒初始化，`ksmbd_vfs_stream_write()` 會先分配一塊記憶體給他 [6]，之後再把要寫入的資料複製到該記憶體內 [7]。然而，當傳入的 offset (`*pos`) 為負數時，複製資料時就會觸發 out-of-bound write。

``` c
static int ksmbd_vfs_stream_write(struct ksmbd_file *fp, char *buf, loff_t *pos,
                  size_t count)
{
    char *stream_buf = NULL, *wbuf;
    // [...]
    wbuf = kvzalloc(size, GFP_KERNEL); // [6]
    // [...]
    stream_buf = wbuf;
    memcpy(&stream_buf[*pos], buf, count); // [7]
    // [...]
}
```

對 ksmbd 熟悉的朋友可能會知道，執行 command handler 前會先呼叫 `smb2_get_data_area_len()`。該 function 會根據不同的 command，檢查傳入的欄位是否合法，但他並沒有檢查有問題的欄位 `Offset`。

``` c
static int smb2_get_data_area_len(unsigned int *off, unsigned int *len,
                  struct smb2_hdr *hdr)
{
    switch (hdr->Command) {
    // [...]
    case SMB2_WRITE:
        if (((struct smb2_write_req *)hdr)->DataOffset ||
            ((struct smb2_write_req *)hdr)->Length) {
            // [8]
            *off = max_t(unsigned short int,
                     le16_to_cpu(((struct smb2_write_req *)hdr)->DataOffset),
                     offsetof(struct smb2_write_req, Buffer));
            *len = le32_to_cpu(((struct smb2_write_req *)hdr)->Length);
            break;
        }

        *off = le16_to_cpu(((struct smb2_write_req *)hdr)->WriteChannelInfoOffset);
        *len = le16_to_cpu(((struct smb2_write_req *)hdr)->WriteChannelInfoLength);
        break;
    // [...]
    }

    if (*off > 4096) {
        // [...]
        ret = -EINVAL;
    } else if ((u64)*off + *len > MAX_STREAM_PROT_LEN) {
        // [...]
        ret = -EINVAL;
    }

    return ret;
}
```

## Day3 (1/29) vsock/virtio: cancel close work in the destructor
> [Commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net?id=df137da9d6d166e87e40980e36eb8e0bc90483ef)

AF_VSOCK 是一種 socket family，用於處理 hypervisor 與 guest 之間的溝通。Function `vsock_assign_transport()` 會在一個 vsock 進行連線時被呼叫。當該 function 檢查 socket 已經初始化過 transport 時，會依序執行 release handler [1] 與 destructor [2]。

``` c
int vsock_assign_transport(struct vsock_sock *vsk, struct vsock_sock *psk)
{
    // [...]
    if (vsk->transport) {
        // [...]
        vsk->transport->release(vsk); // [1]
        vsock_deassign_transport(vsk);
    }
}

static void vsock_deassign_transport(struct vsock_sock *vsk)
{
    // [...]
    vsk->transport->destruct(vsk); // [2]
    // [...]
    vsk->transport = NULL;
}
```

以 Loopback 類型的 transport 為例，release handler 與 destructor 分別為 `virtio_transport_release()` 以及 `virtio_transport_destruct()`。

``` c
static struct virtio_transport loopback_transport = {
    .transport = {
        // [...]
        .destruct = virtio_transport_destruct,
        .release = virtio_transport_release,
        // [...]
    }
    // [...]
};
```

Release handler (`virtio_transport_destruct()`) 會呼叫 `virtio_transport_close()` [3] 來關閉 transport。該 function 會在一些條件下，延遲 close socket 的執行。實際上是 dispatch 給 worker 來執行 [4]。

``` c
void virtio_transport_release(struct vsock_sock *vsk)
{
    struct sock *sk = &vsk->sk;
    bool remove_sock = true;

    if (sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_SEQPACKET)
        remove_sock = virtio_transport_close(vsk); // [3]

    if (remove_sock) {
        // [...]
    }
}

static bool virtio_transport_close(struct vsock_sock *vsk)
{
    struct sock *sk = &vsk->sk;

    // [...]
    sock_hold(sk); // refcount++
    INIT_DELAYED_WORK(&vsk->close_work,
              virtio_transport_close_timeout); // [4]
    vsk->close_work_scheduled = true;
    schedule_delayed_work(&vsk->close_work, VSOCK_CLOSE_TIMEOUT);
    return false;
}
```

Destructor (`virtio_transport_release()`) 則會釋放 bind 在該 vsock transport 的 `virtio_vsock_sock` object [5]。

``` c
void virtio_transport_destruct(struct vsock_sock *vsk)
{
    struct virtio_vsock_sock *vvs = vsk->trans;

    kfree(vvs); // [5]
    vsk->trans = NULL;
}
```

如果 close callback function `virtio_transport_close_timeout()` 發現 socket 的 `SOCK_DONE` flag 沒有設起來 [6]，就會先呼叫 `virtio_transport_reset()` 發送 `VIRTIO_VSOCK_OP_RST` packet 給 Loopback vsock worker，接著呼叫 `virtio_transport_do_close()` 來關閉 vsock [7]。

``` c
static void virtio_transport_close_timeout(struct work_struct *work)
{
    struct vsock_sock *vsk =
        container_of(work, struct vsock_sock, close_work.work);
    struct sock *sk = sk_vsock(vsk);

    sock_hold(sk); // refcount++
    lock_sock(sk);

    if (!sock_flag(sk, SOCK_DONE)) { // [6]
        virtio_transport_reset(vsk, NULL);
        virtio_transport_do_close(vsk, false); // [7]
    }

    vsk->close_work_scheduled = false;

    release_sock(sk);
    sock_put(sk); // refcount--
}
```

`virtio_transport_do_close()` 會 mark socket 成 `SOCK_DONE`，之後呼叫 `vsock_stream_has_data()` 檢查 socket 內是否還有資料仍未處理，有的話會把 TCP 的狀態更新成關閉中 [8]。參考先前介紹的執行流程，該 function 會接著呼叫 `virtio_transport_remove_sock()` [9] 從 global object 移除與此 vsock 有關的 bound 與 connected vsock 資訊。

``` c
static void virtio_transport_do_close(struct vsock_sock *vsk,
                      bool cancel_timeout /* false */)
{
    struct sock *sk = sk_vsock(vsk);

    sock_set_flag(sk, SOCK_DONE);
    vsk->peer_shutdown = SHUTDOWN_MASK;
    if (vsock_stream_has_data(vsk) <= 0)
        sk->sk_state = TCP_CLOSING; // [8]
    sk->sk_state_change(sk);

    if (vsk->close_work_scheduled && // true
        (!cancel_timeout || cancel_delayed_work(&vsk->close_work))) {
        vsk->close_work_scheduled = false;

        virtio_transport_remove_sock(vsk); // [9]
        sock_put(sk); // refcount--
    }
}
```

不論是 `vsock_stream_has_data()` [10] 還是 `virtio_transport_remove_sock()` [11]，都會存取到 bind 在 transport 的 `virtio_vsock_sock` object，但有可能該 object 已經提前在 destructor (`virtio_transport_destruct()`) 被釋放掉，這樣就會有 **Use-After-Free** 的錯誤。

``` c
s64 vsock_stream_has_data(struct vsock_sock *vsk)
{
    return vsk->transport->stream_has_data(vsk); // <-----------------, &virtio_transport_stream_has_data
}

s64 virtio_transport_stream_has_data(struct vsock_sock *vsk)
{
    struct virtio_vsock_sock *vvs = vsk->trans;
    s64 bytes;

    spin_lock_bh(&vvs->rx_lock); // [10]
    bytes = vvs->rx_bytes; // [10]
    spin_unlock_bh(&vvs->rx_lock); // [10]

    return bytes;
}

static void virtio_transport_remove_sock(struct vsock_sock *vsk)
{
    struct virtio_vsock_sock *vvs = vsk->trans;
    // [...]
    __skb_queue_purge(&vvs->rx_queue); // [11]
    // [...]
}
```

Patch 確保了再釋放 `virtio_vsock_sock` object 之前 callback function 已經執行完。

``` diff
@@ -1109,6 +1112,8 @@ void virtio_transport_destruct(struct vsock_sock *vsk)
 {
     struct virtio_vsock_sock *vvs = vsk->trans;
 
+    virtio_transport_cancel_close_work(vsk, true);
+
     kfree(vvs);
     vsk->trans = NULL;
 }
```

Function `virtio_transport_cancel_close_work()` 會呼叫 `cancel_delayed_work()`。如果 work 正在執行，那就等到他執行結束；如果 work 為 pending 狀態，就直接取消。這樣就可以確保會使用到 `virtio_vsock_sock` object 的 callback function 會在 destructor 釋放此 object 之前就執行完。

``` c
static void virtio_transport_cancel_close_work(struct vsock_sock *vsk,
                           bool cancel_timeout)
{
    struct sock *sk = sk_vsock(vsk);

    if (vsk->close_work_scheduled &&
        (!cancel_timeout || cancel_delayed_work(&vsk->close_work))) {
        vsk->close_work_scheduled = false;

        virtio_transport_remove_sock(vsk);
        sock_put(sk);
    }
}
```

## Day4 (1/30) xsk: fix OOB map writes when deleting elements
> [Commit](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=32cd3db7de97c0c7a018756ce66244342fd583f0)

AF_XDP 是一種 socket family，是 XDP (express data path) interface，用 eBPF 在網路封包進到 stack 前就先過濾一次的機制。此種類型的 socket 需要在當前 namespace 有 `CAP_NET_RAW` 權限才能建立 [1]。

``` c
static const struct net_proto_family xsk_family_ops = {
    .family = PF_XDP,
    .create = xsk_create, // <------------
    .owner    = THIS_MODULE,
};

static int xsk_create(struct net *net, struct socket *sock, int protocol,
              int kern)
{
    // [...]
    
    if (!ns_capable(net->user_ns, CAP_NET_RAW)) // [1]
        return -EPERM;
    if (sock->type != SOCK_RAW)
        return -ESOCKTNOSUPPORT;
    if (protocol)
        return -EPROTONOSUPPORT;

    // [...]
}
```

該漏洞的 patch 將 function `xsk_map_delete_elem()` 內的 `k` 變數從 signed 改成 unsigned。

``` diff
@@ -224,7 +224,7 @@ static long xsk_map_delete_elem(struct bpf_map *map, void *key)
     struct xsk_map *m = container_of(map, struct xsk_map, map);
     struct xdp_sock __rcu **map_entry;
     struct xdp_sock *old_xs;
-    int k = *(u32 *)key;
+    u32 k = *(u32 *)key;
```

該 function 用來在 eBPF program 中刪除 XSK map 的 element。XSK 指的就是 XDP socket，而 XSK map 為 eBPF program 中用來存放 XDP socket 的記憶體空間。

``` c
const struct bpf_map_ops xsk_map_ops = {
    // [...]
    .map_update_elem = xsk_map_update_elem,
    .map_delete_elem = xsk_map_delete_elem,
    // [...]
};
```

不過如果要在 eBPF program 中使用這種類型的 map，需要在 init namespace 中有 root 的權限 [2]，因此一般使用者存取不到。

``` c
#if defined(CONFIG_XDP_SOCKETS)
BPF_MAP_TYPE(BPF_MAP_TYPE_XSKMAP, xsk_map_ops)
#endif

static int map_create(union bpf_attr *attr)
{
    // [...]
    switch (map_type) {
        // [...]
        case BPF_MAP_TYPE_XSKMAP:
        if (!capable(CAP_NET_ADMIN)) // [2]
            return -EPERM;
        break;
        // [...]
    }
}
```

因為 key 是使用者可控，加上 `xsk_map_delete_elem()` 並沒有對 key value 的 lower bound 做檢查 [3]，因此在存取 map entry 時就會觸發 Out-Of-Bounds access [4, 5]。

``` c
static long xsk_map_delete_elem(struct bpf_map *map, void *key)
{
    struct xsk_map *m = container_of(map, struct xsk_map, map);
    struct xdp_sock __rcu **map_entry;
    struct xdp_sock *old_xs;
    int k = *(u32 *)key;

    if (k >= map->max_entries) // [3]
        return -EINVAL;

    spin_lock_bh(&m->lock);
    map_entry = &m->xsk_map[k]; // [4]
    old_xs = unrcu_pointer(xchg(map_entry, NULL));
    if (old_xs)
        xsk_map_sock_delete(old_xs, map_entry); // [5]
    spin_unlock_bh(&m->lock);

    return 0;
}
```

## Day5 (1/31) af_packet: fix vlan_get_tci() vs MSG_PEEK
> [Commit](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=7aa78d0d8546d8ce5a764add3f55d72e707c18f1)

Patch 調整了 function `vlan_get_tci()` 的執行邏輯，我們需要先知道怎麼走到這個 function。

AF_PACKET 為 Linux kernel Low-level packet interface 的實作。當建立一個 AF_PACKET socket 時，會由 AF_PACKET 的 create handler `packet_create()` 來處理。

``` c
static const struct net_proto_family packet_family_ops = {
    .family =    PF_PACKET,
    .create =    packet_create,
    // [...]
};
```

`packet_create()` 檢查是否 process 在當前 namespace 有足夠的權限 [1]，並且只支援部分的 socket type [2]。新增的 socket 其 type ops 為 `packet_ops`。

``` c
static int packet_create(struct net *net, struct socket *sock, int protocol,
             int kern)
{
    // [...]
    if (!ns_capable(net->user_ns, CAP_NET_RAW)) // [1]
        return -EPERM;
    if (sock->type != SOCK_DGRAM && sock->type != SOCK_RAW && // [2]
        sock->type != SOCK_PACKET)
        return -ESOCKTNOSUPPORT;
    // [...]
    sock->ops = &packet_ops;
    // [...]
}
```

當 AF_PACKET socket 呼叫 `sys_recvmsg()` 時，底層會由 recvmsg handler `packet_recvmsg()` 來處理 [3]。在解析封包時，如果 packet socket 的 `PACKET_SOCK_AUXDATA` flag 有被設上 [4]，就會用 control block (CB) 內的 interface index 來取的對應的 device object [5]，並以此為參數呼叫 `vlan_get_tci()` [6]。

``` c
static const struct proto_ops packet_ops = {
    .family   =  PF_PACKET,
    // [...]
    .sendmsg  =  packet_sendmsg,
    .recvmsg  =  packet_recvmsg, // [3]
    // [...]
};

#define PACKET_SKB_CB(__skb)    ((struct packet_skb_cb *)((__skb)->cb))
static int packet_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
              int flags)
{
    struct sock *sk = sock->sk;
    // [...]
    skb = skb_recv_datagram(sk, flags, &err);

    // [...]
    if (packet_sock_flag(pkt_sk(sk), PACKET_SOCK_AUXDATA)) { // [4]
        struct sockaddr_ll *sll = &PACKET_SKB_CB(skb)->sa.ll;
        // [...]
        else if (unlikely(sock->type == SOCK_DGRAM && eth_type_vlan(skb->protocol))) {
            dev = dev_get_by_index_rcu(sock_net(sk), sll->sll_ifindex); // [5]
            if (dev) {
                aux.tp_vlan_tci = vlan_get_tci(skb, dev); // [6]
                // [...]
            }
        }
    }
}
```

`vlan_get_tci()` 用來從 packet 中取得 VLAN 標記 (TCI, Tag Control Information)。該 function 會先呼叫 `skb_push()` 來調整 packet object 的 metadata [7]，再取得封包內容並回傳 [8]。

``` c
static u16 vlan_get_tci(struct sk_buff *skb, struct net_device *dev)
{
    u8 *skb_orig_data = skb->data;
    int skb_orig_len = skb->len;
    struct vlan_hdr vhdr, *vh;
    unsigned int header_len;

    // [...]
    skb_push(skb, skb->data - skb_mac_header(skb)); // [7]
    vh = skb_header_pointer(skb, header_len, sizeof(vhdr), &vhdr);
    // [...]
    return ntohs(vh->h_vlan_TCI); // [8]
}

void *skb_push(struct sk_buff *skb, unsigned int len)
{
    skb->data -= len;
    skb->len  += len;
    if (unlikely(skb->data < skb->head))
        skb_under_panic(skb, len, __builtin_return_address(0));
    return skb->data;
}
```

然而，用於取得 packet object 的 function `skb_recv_datagram()` 會在底層呼叫 `__skb_try_recv_from_queue()`，並在 syscall 的參數 `flags` 有包含 `MSG_PEEK` 時更新 refcount 就回傳 packet object [9]，而不是從 packet queue 中移除 [10]。

``` c
struct sk_buff *__skb_try_recv_from_queue(/* ... */)
{
    bool peek_at_off = false;
    struct sk_buff *skb;
    int _off = 0;

    // [...]
    *last = queue->prev;
    skb_queue_walk(queue, skb) {
        if (flags & MSG_PEEK) {
            // [...]
            refcount_inc(&skb->users); // [9]
        } else {
            __skb_unlink(skb, queue); // [10]
        }
        // [...]
        return skb;
    }
    // [...]
}
```

也就是說，我們可以透過 `MSG_PEEK` 不斷觸發 `skb_push()`，這樣就能夠一直更新 skb metadata。直到 data pointer 比 header 還要前面時，function `skb_under_panic()` 就會被執行並觸發 kernel panic。

而 patch 則是將 `vlan_get_tci()` 的參數 `skb` 改成 const pointer，確保該 object 的成員不會在 function 內被更新。
