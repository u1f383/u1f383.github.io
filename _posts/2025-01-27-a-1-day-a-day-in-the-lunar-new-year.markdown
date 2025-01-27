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
