---
layout: post
title:  "Linux Kernel Vsock 1-day Analysis"
categories: linux
---

After completing my talk at POC 2024 and Pwn2Own Ireland 2024, I finally have time to explore new attack surfaces in the Linux kernel for kernelCTF. With new exploit slots and recent blog posts available, I plan to spend approximately two weeks analyzing them for fresh insights.

To start, I've chosen to examine exp196 and exp197, which were exploited by Theori team. This vulnerability is related to the VirtIo. While I haven't yet not successfully reproduced it, here is some of my analysis so far. For more details, you can refer the [commit log](https://git.kernel.org/pub/scm/linux/kernel/git/mst/vhost.git/commit/?h=vhost&id=6ca575374dd9a507cdd16dfa0e78c2e9e20bd05f).

## 1. Overview

The diff is very simple and straightforward: a new line is added to reset `vsk->trans`. This is a common bug pattern: after freeing an object, the kernel forgets to update other objects that have fields referring to it (e.g., CVE-2023-5345).
``` diff
--- a/net/vmw_vsock/virtio_transport_common.c
+++ b/net/vmw_vsock/virtio_transport_common.c
@@ -1109,6 +1109,7 @@ void virtio_transport_destruct(struct vsock_sock *vsk)
    struct virtio_vsock_sock *vvs = vsk->trans;

    kfree(vvs);
+   vsk->trans = NULL;
 }
 EXPORT_SYMBOL_GPL(virtio_transport_destruct);
```

Based on the information provided by commit log, this function serves as the destructor of `loopback_transport`, which releases the `virtio_vsock_sock` member of the `vsock_sock` object.
``` c
static struct virtio_transport loopback_transport = {
    .transport = {
        // [...]
        .init                     = virtio_transport_do_socket_init,
        .destruct                 = virtio_transport_destruct,
        // [...]
    },
}
```

The `vsock_deassign_transport()` function calls the destructor [1] and then sets `vsk->transport` to NULL [2].
``` c
static void vsock_deassign_transport(struct vsock_sock *vsk)
{
    // [...]
    vsk->transport->destruct(vsk); // [1]
    module_put(vsk->transport->module);
    vsk->transport = NULL; // [2]
}
```

One scenario where `vsock_deassign_transport()` might be invoked is updating the target transport for a new connection [3]. The transport object `vsk->transport` is initialized for each connection [4]. If a connection attempt fails and the socket retries with a different transport, the old transport object is checked [5] and released.
``` c
int vsock_assign_transport(struct vsock_sock *vsk, struct vsock_sock *psk)
{
    // [...]
    switch (sk->sk_type) {
    case SOCK_STREAM:
    case SOCK_SEQPACKET:
        if (vsock_use_local_transport(remote_cid))
            new_transport = transport_local;
        else if (remote_cid <= VMADDR_CID_HOST || !transport_h2g ||
             (remote_flags & VMADDR_FLAG_TO_HOST))
            new_transport = transport_g2h;
        else
            new_transport = transport_h2g;
        break;
    }
    // [...]
    if (vsk->transport) { // [5]
        if (vsk->transport == new_transport)
            return 0;

        vsk->transport->release(vsk);
        vsock_deassign_transport(vsk); // [3]
    }

    // [...]

    // [4] call `virtio_transport_do_socket_init()`
    ret = new_transport->init(vsk, psk);
    vsk->transport = new_transport;
    return 0;
}

int virtio_transport_do_socket_init(struct vsock_sock *vsk,
                    struct vsock_sock *psk)
{
    struct virtio_vsock_sock *vvs;
    vvs = kzalloc(sizeof(*vvs), GFP_KERNEL);
    vsk->trans = vvs;
    vvs->vsk = vsk;
    // [...]
}
```

The `vsock_assign_transport()` is invoked by `vsock_connect()` [6]. Only unconnected sockets are permitted to have a transport assigned.
``` c
static int vsock_connect(struct socket *sock, struct sockaddr *addr,
             int addr_len, int flags)
{
    // [...]
    switch (sock->state) {
    case SS_CONNECTED:
        err = -EISCONN;
        goto out;
    
    case SS_DISCONNECTING:
        err = -EINVAL;
        goto out;
    
    case SS_CONNECTING:
        err = -EALREADY;
        if (flags & O_NONBLOCK)
            goto out;
        break;
    
    default:
        err = vsock_assign_transport(vsk, NULL); // [6]
        transport = vsk->transport;
        err = transport->connect(vsk);
    }
    // [...]
}

// include/uapi/linux/net.h
typedef enum {
    SS_FREE = 0,
    SS_UNCONNECTED,
    SS_CONNECTING,
    SS_CONNECTED,
    SS_DISCONNECTING
} socket_state;
```

AF_VSOCK sockets with protocols SOCK_SEQPACKET and SOCK_STREAM call the `vsock_connect()` function during `sys_connect`.
``` c
static const struct proto_ops vsock_seqpacket_ops = {
    .family = PF_VSOCK,
    // [...]
    .connect = vsock_connect,
    // [...]
};

static const struct proto_ops vsock_stream_ops = {
    .family = PF_VSOCK,
    // [...]
    .connect = vsock_connect,
    // [...]
};
```

How to determine which types of transports are supported by the kernel, and how to choose the desired transport? According to the `vsock_core_register()` function, there are four transport types (referred to as `features` in the source code).
``` c
int vsock_core_register(const struct vsock_transport *t, int features)
{
    const struct vsock_transport *t_h2g, *t_g2h, *t_dgram, *t_local;
    
    // [...]
    t_h2g = transport_h2g;
    t_g2h = transport_g2h;
    t_dgram = transport_dgram;
    t_local = transport_local;

    if (features & VSOCK_TRANSPORT_F_H2G) {
        t_h2g = t;
    }

    if (features & VSOCK_TRANSPORT_F_G2H) {
        t_g2h = t;
    }

    if (features & VSOCK_TRANSPORT_F_DGRAM) {
        t_dgram = t;
    }

    if (features & VSOCK_TRANSPORT_F_LOCAL) {
        t_local = t;
    }

    transport_h2g = t_h2g;
    transport_g2h = t_g2h;
    transport_dgram = t_dgram;
    transport_local = t_local;

    // [...]
    return err;
}
```

During intialization, subsystems call the `vsock_core_register()` function to register specific transport handlers. For example, in the kernelCTF environemnt:
``` c
static int __init vhost_vsock_init(void)
{
    // [...]
    ret = vsock_core_register(&vhost_transport.transport,
                  VSOCK_TRANSPORT_F_H2G);
    // [...]
}

static int __init virtio_vsock_init(void)
{
    // [...]
    ret = vsock_core_register(&virtio_transport.transport,
                  VSOCK_TRANSPORT_F_G2H);
}

static int __init vsock_loopback_init(void)
{
    // [...]
    ret = vsock_core_register(&loopback_transport.transport,
                  VSOCK_TRANSPORT_F_LOCAL);
    // [...]
}

static int __init vmci_transport_init(void)
{
    // [...]
    err = vsock_core_register(&vmci_transport, VSOCK_TRANSPORT_F_DGRAM);
    // [...]
}
```

We can select the transport type through the `sys_connect` parameter `sockaddr_vm.svm_cid`, using the following values:
- `VMADDR_CID_ANY` (-1U)
- `VMADDR_CID_HYPERVISOR` (0)
- `VMADDR_CID_LOCAL` (1)
- `VMADDR_CID_HOST` (2)

## 2. Proof-Of-Concept

The vulnerable function, `virtio_transport_destruct()`, can be triggered by executing the following C code:
``` c
int main() {
    int sockfd;
    struct sockaddr_vm addr;
    struct timeval timeout;

    sockfd = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_port = VSOCK_PORT;

    timeout.tv_sec = 0;
    timeout.tv_usec = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    addr.svm_cid = VMADDR_CID_LOCAL;
    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    getchar();

    addr.svm_cid = VMADDR_CID_HOST;
    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)); // trigger
    getchar();

    return 0;
}
```

Clearly, you need to find somewhere the race window occurs for using freed `vsk->trans`. However, since the `vsock_connect()` function holds a lock of the socket [1], we cannot simply race two `vsock_connect()` calls simultaneously. The same issue also appears in other protocol handlers.
``` c
static int vsock_connect(struct socket *sock, struct sockaddr *addr,
             int addr_len, int flags)
{
    // [...]

    err = 0;
    sk = sock->sk;
    vsk = vsock_sk(sk);
    lock_sock(sk); // [1]

    // [...]
}
```

So I grep-ed all the uses of `vsk->trans;` and checked whether they could be reached without holding a lock. Unfortunately, all of them hold the lock before accessing `vsk->trans`.
- `virtio_transport_send_pkt_info()`
- `virtio_transport_seqpacket_do_peek()`
- `virtio_transport_seqpacket_do_dequeue()`
- `virtio_transport_seqpacket_enqueue()`
- `virtio_transport_seqpacket_has_data()`
- `virtio_transport_notify_buffer_size()`
- `virtio_transport_remove_sock()`
- `virtio_transport_recv_enqueue()`
- `virtio_transport_space_update()`
- `virtio_transport_read_skb()`
- `virtio_transport_notify_set_rcvlowat()`

Then I'm stuck and have no idea what to try next 😭. Perhaps I missed something important, or I might need to use a different protocol type instead of SOCK_SEQPACKET. I'm not sure yet.

I'll give it another try when I have some free time, and update this post with any new progress.