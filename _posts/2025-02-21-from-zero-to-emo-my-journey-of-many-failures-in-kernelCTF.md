---
layout: post
title:  "From Zero to Emo – My Journey of Many Failures in kernelCTF"
categories: linux
---

Since the end of 2024, many vulnerabilities exploited in kernelCTF have originated from the net/sched subsystem, often following similar patterns. In short, the － field of a qdisc object represents the number of packets in its child qdisc. Because this field also determines the qdisc's state, logical bugs that violate the `qlen` rule can allow us to manipulate the qdisc state, leading to scenarios where a class object is freed but remains accessible.

While reproducing CVE-2024-56770 as part of a 1-day practice, I accidentally discovered two additional, previously unknown vulnerabilities. Unfortunately, both were exploited by others. One of the reasons I lost the race condition competition was that my exploitation relied on a side-channel attack to leak KASLR, which was unstable on a busy machine. I have no idea how to leak KASLR in this scenario and am still waiting for the reporter to share their techniques.

In this post, I will analyze these three vulnerabilities: CVE-2024-56770, CVE-2025-21703 (a variant of CVE-2024-56770), and CVE-2025-21700. I also provides the POCs to control RIP or trigger kernel panic. I will not introduce the basic knowledge of net/sched here. Please check my previous posts for that. Thank you!

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

### What's next ?

If we can violate the `qlen` rule, we can leverage the Deficit Round Robin (DRR) scheduler object to control RIP.

The function `qdisc_tree_reduce_backlog()` **should be called** each time `qlen` is updated. First, if both the packet length and data size are zero, the function simply returns early [1]. Then, if the `qlen` of a child qdisc drops to zero [2], the qlen notification handler of the parent qdisc is invoked [3]. The implementation of qlen notification handlers varies depending on the scheduler.

``` c
void qdisc_tree_reduce_backlog(struct Qdisc *sch, int n, int len)
{
    bool qdisc_is_offloaded = sch->flags & TCQ_F_OFFLOADED;
    const struct Qdisc_class_ops *cops;
    unsigned long cl;
    u32 parentid;
    bool notify;
    int drops;

    if (n == 0 && len == 0) // [1]
        return;
    drops = max_t(int, n, 0);
    //
    while ((parentid = sch->parent)) {
        // [...]
        notify = !sch->q.qlen /* [2] */ && !WARN_ON_ONCE(!n &&
                               !qdisc_is_offloaded);
        sch = qdisc_lookup_rcu(qdisc_dev(sch), TC_H_MAJ(parentid));
        cops = sch->ops->cl_ops;
        if (notify && cops->qlen_notify) {
            cl = cops->find(sch, parentid);
            cops->qlen_notify(sch, cl); // [3]
        }
        sch->q.qlen -= n;
        // [...]
    }
    // [...]
}
```

This function is also called in some delete handlers of schedulers. For example, before the DRR delete handler, `drr_delete_class()`, releases a class object, it calls `qdisc_purge_queue()` [4] to purge all enqueued packets of the associated qdisc object. This function then calls `qdisc_tree_reduce_backlog()` to propagate the update to its parent qdisc [5].

``` c
static int drr_delete_class(struct Qdisc *sch, unsigned long arg,
                struct netlink_ext_ack *extack)
{
    struct drr_sched *q = qdisc_priv(sch);
    struct drr_class *cl = (struct drr_class *)arg;

    // [...]
    qdisc_purge_queue(cl->qdisc); // [4]

    // [...]
    return 0;
}

static inline void qdisc_purge_queue(struct Qdisc *sch)
{
    __u32 qlen, backlog;

    qdisc_qstats_qlen_backlog(sch, &qlen, &backlog);
    qdisc_reset(sch);
    qdisc_tree_reduce_backlog(sch, qlen, backlog); // [5]
}
```

The qlen notification handler must ensure that there are no external references to the class object; otherwise, it could result in a UAF vulnerability.

The DRR notification handler, `drr_qlen_notify()`, removes the class object from the active list [6].

``` c
static void drr_qlen_notify(struct Qdisc *csh, unsigned long arg)
{
    struct drr_class *cl = (struct drr_class *)arg;

    list_del(&cl->alist); // [6]
}
```

A DRR class object is inserted into the active list [7] if it is sending a packet for the first time [8].

``` c
static int drr_enqueue(struct sk_buff *skb, struct Qdisc *sch,
               struct sk_buff **to_free)
{
    unsigned int len = qdisc_pkt_len(skb);
    struct drr_sched *q = qdisc_priv(sch);
    struct drr_class *cl;
    int err = 0;
    bool first;

    cl = drr_classify(skb, sch, &err);
    // [...]
    first = !cl->qdisc->q.qlen; // [8]
    err = qdisc_enqueue(skb, cl->qdisc, to_free);
    // [...]
    if (first) {
        list_add_tail(&cl->alist, &q->active); // [7]
        cl->deficit = cl->quantum;
    }

    // [...]
    return err;
}
```

We first bind a netem qdisc to a DRR class object and then trigger the vulnerability. The `netem_dequeue()` function drops `qlen` without calling `qdisc_tree_reduce_backlog()`, preventing the DRR qlen notification handler from being invoked to remove the class object from the active list. As a result, when deleting a DRR class object, the delete handler sees that `qlen` and data size are both zero and takes no action.

However, the class object remains in the active list, which can lead to a UAF if the kernel retrieves the class object from the active list — this occurs in the DRR dequeue handler, `drr_dequeue()`.

The `drr_dequeue()` function retrieves a class object from the active list and then calls the `peek` [9] function pointer from the class ops.

``` c
static struct sk_buff *drr_dequeue(struct Qdisc *sch)
{
    struct drr_sched *q = qdisc_priv(sch);
    struct drr_class *cl;
    struct sk_buff *skb;
    unsigned int len;

    if (list_empty(&q->active))
        goto out;
    
    while (1) {
        cl = list_first_entry(&q->active, struct drr_class, alist);
        skb = cl->qdisc->ops->peek(cl->qdisc); // [9]
        // [...]
    }
}
```

If we reclaim the class object, we can control the `qdisc` member and ultimately gain control over the RIP.

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

The exploitation method is the same as CVE-2024-56770.

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

    // [...]
    while ((parentid = sch->parent)) {
        if (parentid == TC_H_ROOT) // [1]
            break;

        // [...]
        notify = !sch->q.qlen && !WARN_ON_ONCE(!n &&
                               !qdisc_is_offloaded);
        
        sch = qdisc_lookup_rcu(qdisc_dev(sch), TC_H_MAJ(parentid)); // [2]
        // [...]

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

The exploitation method is the same as CVE-2024-56770.