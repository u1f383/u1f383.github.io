---
layout: post
title:  "From Zero to Emo – My Journey of Many Failures in kernelCTF"
categories: linux
---

Since the end of 2024, many vulnerabilities exploited in kernelCTF have originated from the net/sched subsystem, often following similar patterns. In short, the － field of a qdisc object represents the number of packets in its child qdisc. Because this field also determines the qdisc's state, logical bugs that violate the `qlen` rule can allow us to manipulate the qdisc state, leading to scenarios where a class object is freed but remains accessible.

While reproducing CVE-2024-56770 as part of a 1-day practice, I accidentally discovered two additional, previously unknown vulnerabilities. Unfortunately, both were exploited by others. One of the reasons I lost the race condition competition was that my exploitation relied on a side-channel attack to leak KASLR, which was unstable on a busy machine. I have no idea how to leak KASLR in this scenario and am still waiting for the reporter to share their techniques.

In this post, I will analyze these three vulnerabilities: CVE-2024-56770, CVE-2025-21703 (a variant of CVE-2024-56770), and CVE-2025-21700. I also provides the POCs to control RIP.

## 1. CVE-2024-56770 - net/sched: netem: account for backlog updates from child qdisc

The commit is [here](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f8d4bc455047cf3903cd6f85f49978987dbb3027), and the POC is [here](/assets/cve-2024-56770-poc.c).

The netem (network emulation) scheduler supports delaying the packet transmission, and the packet will be temporarily stored in the tfifo queue by the function `tfifo_enqueue()`. This function increments `sch->q.qlen` by 1 [1], whihc means that the number of packets in the tfifo queue is also recorded by `qlen` field.

The netem (Network Emulation) scheduler supports delaying packet transmission, temporarily storing packets in the tfifo queue using the `tfifo_enqueue()` function. This function increments `sch->q.qlen` by 1 [1], indicating that the number of packets in the tfifo queue is also tracked by the `qlen` field.

``` c
static void tfifo_enqueue(struct sk_buff *nskb, struct Qdisc *sch)
{
    struct netem_sched_data *q = qdisc_priv(sch);
    
    // [...]
    sch->q.qlen++; // [1]
}
```

During dequeuing, the `netem_dequeue()` function peeks at a packet and checks whether the delay time has elapsed before sending it. However, this function decrements `sch->q.qlen` by 1 [2] and enqueues the packet into the child qdisc. This behavior is incorrect because the `qlen` value of the scheduler should represent the **total packet count** across its child qdiscs.

``` c
static struct sk_buff *netem_dequeue(struct Qdisc *sch)
{
    // [...]
    skb = netem_peek(q);
    if (skb) {
        // [...]
        time_to_send = netem_skb_cb(skb)->time_to_send;
        if (time_to_send <= now && q->slot.slot_next <= now) {
            // [...]
            sch->q.qlen--; // [2]

            if (q->qdisc) {
                unsigned int pkt_len = qdisc_pkt_len(skb);
                struct sk_buff *to_free = NULL;
                int err;

                err = qdisc_enqueue(skb, q->qdisc, &to_free);
                // [...]
                goto tfifo_dequeue;
            }
        }
    }
}
```

## 2. CVE-2025-21703 - netem: Update sch->q.qlen before qdisc_tree_reduce_backlog()

The commit is [here](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=638ba5089324796c2ee49af10427459c2de35f71), and the POC is [here](/assets/cve-2025-21703-poc.c).

The patch for CVE-2024-56770 led to another issue. The `qlen` update should propagate to the parent qdisc. However, the propagation function `qdisc_tree_reduce_backlog()` is called [1] before `qlen` is decremented by 1 [2], causing a mismatch in the number of packets between the child and parent.

``` c
static struct sk_buff *netem_dequeue(struct Qdisc *sch)
{
    // [...]
    if (q->qdisc) {
        unsigned int pkt_len = qdisc_pkt_len(skb);
        struct sk_buff *to_free = NULL;
        int err;

        err = qdisc_enqueue(skb, q->qdisc, &to_free);
        kfree_skb_list(to_free);
        if (err != NET_XMIT_SUCCESS) {
            // [...]
            qdisc_tree_reduce_backlog(sch, 1, pkt_len); // [1]
            sch->qstats.backlog -= pkt_len;
            sch->q.qlen--; // [2]
        }
        goto tfifo_dequeue;
    }
    // [...]
}
```

## 3. CVE-2025-21700 - net: sched: Disallow replacing of child qdisc from one parent to another

The commit is [here](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=bc50835e83f60f56e9bec2b392fb5544f250fb6f), and the POC is [here](/assets/cve-2025-21700-poc.c).

Each time `qlen` is updated, the function `qdisc_tree_reduce_backlog()` is called to propagate the change to the parent and ancestors until it reaches the root qdisc [1]. During creation, the `parent` field of a qdisc is set to the parent ID, and this field is used as a parameter in the function `qdisc_lookup_rcu()` to retrieve the parent qdisc [2].

``` c
void qdisc_tree_reduce_backlog(struct Qdisc *sch, int n, int len)
{
    bool qdisc_is_offloaded = sch->flags & TCQ_F_OFFLOADED;
    const struct Qdisc_class_ops *cops;
    unsigned long cl;
    u32 parentid;
    bool notify;
    int drops;

    // [...]
    while ((parentid = sch->parent)) {
        if (parentid == TC_H_ROOT) // [1]
            break;

        // [...]
        notify = !sch->q.qlen && !WARN_ON_ONCE(!n &&
                               !qdisc_is_offloaded);
        
        sch = qdisc_lookup_rcu(qdisc_dev(sch), TC_H_MAJ(parentid)); // [2]
        // [...]
        cops = sch->ops->cl_ops;
        if (notify && cops->qlen_notify) {
            cl = cops->find(sch, parentid);
            cops->qlen_notify(sch, cl);
        }
        sch->q.qlen -= n;
        // [...]
    }
    // [...]
}
```

The net/sched subsystem supports the **graft** operation, which allows moving a qdisc object from one subtree to another. The graft request is handled by the function `qdisc_graft()`. However, the graft operation does not update the parent ID, meaning that `qlen` propagation affects the original subtree instead of the new one.

``` c
static int qdisc_graft(struct net_device *dev, struct Qdisc *parent,
               struct sk_buff *skb, struct nlmsghdr *n, u32 classid,
               struct Qdisc *new, struct Qdisc *old,
               struct netlink_ext_ack *extack)
{
    // [...]
    else {
        const struct Qdisc_class_ops *cops = parent->ops->cl_ops;
        unsigned long cl;
        int err;
        
        cl = cops->find(parent, classid);
        err = cops->graft(parent, cl, new, &old, extack);
    }
}
```

The patch disallows moving a qdisc to a different parent subtree.

``` diff
--- a/net/sched/sch_api.c
+++ b/net/sched/sch_api.c
@@ -1664,6 +1664,10 @@ replay:
                 q = qdisc_lookup(dev, tcm->tcm_handle);
                 if (!q)
                     goto create_n_graft;
+                if (q->parent != tcm->tcm_parent) {
+                    NL_SET_ERR_MSG(extack, "Cannot move an existing qdisc to a different parent");
+                    return -EINVAL;
+                }
```