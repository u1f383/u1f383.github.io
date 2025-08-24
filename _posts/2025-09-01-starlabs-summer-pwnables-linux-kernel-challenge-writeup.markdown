---
layout: post
title:  "STAR Labs Summer Pwnables Linux Kernel Challenge Writeup"
categories: Linux
---

Recently, STAR Labs created some [Pwn challenges](https://starlabs.sg/blog/2025/08-updates-summer-pwnables/) for Singaporean students, and one of them was related to the Linux kernel. I know the Linux kernel researchers at STAR Labs are very skilled, so I thought this challenge would be interesting and that I might learn or practice some skills in the process. In the end, I spent about one to two days (not full-time) solving it, and my exploit doesn’t seem to be the intended solution (which is quite common for Linux kernel challenges).

This post simply records my process of solving the challenge, including the problems I got stuck on and how I overcame them. Thanks to the author for creating this challenge, and to Billy for sending it to me.

## 1. Introduction

This kernel module exposes the device `"/dev/paradox_engine"`, and it defines three core structures: session, timeline, and event. Each time the device is opened, a new session is created [1]. The open handler then creates a default timeline [2] for the session, along with an event for the newly created timeline [3]. Note that events are allocated from a dedicated slab cache, `"temporal_event_cache"`, which is used exclusively by this structure.

The entire process also involves ID assignment and linked list updates, but I will skip those details here since they are fairly standard operations.

``` c
static int paradox_engine_open(struct inode *inode, struct file *filp) {
    struct paradox_session_data *session = kzalloc(sizeof(*session), GFP_KERNEL); // [1]
    // [...]

    struct timeline *primordial_tl = kzalloc(sizeof(*primordial_tl), GFP_KERNEL); // [2]
    // [...]
    list_add_tail(&primordial_tl->session_node, &session->all_timelines);

    struct temporal_event *first_cause = kmem_cache_alloc(temporal_event_cache, GFP_KERNEL|__GFP_ZERO); // [3]
    // [...]
    list_add_tail(&first_cause->timeline_node, &primordial_tl->events_head);

    filp->private_data = session;
    return 0;
}
```

When a session is closed, the handler first iterates through all timelines [4]. For each timeline, it then iterates through all events [5] and attempts to release them. Since an event may depend on another event, a while loop is used to traverse the dependency linked list [6] and release those dependencies.

Finally, the timeline linked list is iterated again at the end of the function [7], and each timeline is freed after its bound event is unbound [8].

``` c
static int paradox_engine_release(struct inode *inode, struct file *filp) {
    struct paradox_session_data *session = filp->private_data;
    struct timeline *tl, *tmp_tl;
    struct temporal_event *event, *tmp_event;

    list_for_each_entry(tl, &session->all_timelines, session_node) { // [4]
        list_for_each_entry_safe(event, tmp_event, &tl->events_head, timeline_node) { // [5]
            
            struct temporal_event *cause = event->causal_dependency;
            list_del(&event->timeline_node);
            while (cause) { // [6]
                struct temporal_event *next_in_chain = cause->causal_dependency;
                event_put(cause);
                cause = next_in_chain;
            }
            
            event->causal_dependency = NULL;
            event_put(event);
        } 
    }
    

    list_for_each_entry_safe(tl, tmp_tl, &session->all_timelines, session_node) { // [7]
        list_del(&tl->session_node);
        
        if (tl->caused_by_event)
            event_put(tl->caused_by_event); // [8]
        kfree(tl);
    }

    kfree(session);
    return 0;
}
```

The ioctl interface supports two commands: `PARADOX_CREATE_TIMELINE` and `PARADOX_CREATE_EVENT`. The former creates a new timeline object and binds it to an existing event [9], while the latter creates a new event for a specified timeline. Additionally, it allows the user to establish a dependency between the new event and another existing event [10].

``` c
static long paradox_engine_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct paradox_session_data *session = filp->private_data;
    struct timeline *target_tl = NULL, *tmp_tl;
    long ret = 0;
    
    // [...]
    switch (cmd) {
        case PARADOX_CREATE_TIMELINE:
            {
                struct paradox_timeline_req req;
                copy_from_user(&req, (void __user *)arg, sizeof(req));
                // [...]
                
                struct temporal_event *cause_event = NULL;
                list_for_each_entry(tmp_tl, &session->all_timelines, session_node) {
                    if(tmp_tl->timeline_id == req.cause_timeline_id) {
                        cause_event = find_event_in_timeline(tmp_tl, req.cause_event_id);
                        if(cause_event) break;
                    }
                }

                // [...]
                struct timeline *new_tl = kzalloc(sizeof(*new_tl), GFP_KERNEL);
                // [...]
                new_tl->caused_by_event = cause_event; // [9]
                event_get(cause_event);
                list_add_tail(&new_tl->session_node, &session->all_timelines);
                req.new_timeline_id = new_tl->timeline_id;
                // [...]
            }

        case PARADOX_CREATE_EVENT:
            {
                struct paradox_event_req req;
                copy_from_user(&req, (void __user *)arg, sizeof(req));
                // [...]
                list_for_each_entry(tmp_tl, &session->all_timelines, session_node) {
                    if (tmp_tl->timeline_id == req.target_timeline_id) {
                        target_tl = tmp_tl;
                        break;
                    }
                }

                // [...]
                struct temporal_event *event = kmem_cache_alloc(temporal_event_cache, GFP_KERNEL|__GFP_ZERO);
                // [...]
                event->parent_timeline = target_tl;
                list_add_tail(&event->timeline_node, &target_tl->events_head);
                
                if (req.cause_event_id != 0) {
                    struct temporal_event *cause_event = find_event_in_timeline(target_tl, req.cause_event_id);
                    if (cause_event) {
                        event->causal_dependency = cause_event; // [10]
                        event_get(cause_event);
                    }
                }
                // [...]
                break;
            }
        default:
            // [...]
    }
    // [...]
}
```

## 2. Vulnerability

The vulnerability is straightforward: before a dependency is established, the event object is already accessible through the timeline’s linked list [1]. As a result, it is possible for an event to be set as a dependency of itself.

``` c
static long paradox_engine_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        // [...]
        case PARADOX_CREATE_EVENT:
        {
            struct temporal_event *event = kmem_cache_alloc(temporal_event_cache, GFP_KERNEL|__GFP_ZERO);
            // [...]
            list_add_tail(&event->timeline_node, &target_tl->events_head); // [1]
            
            if (req.cause_event_id != 0) {
                struct temporal_event *cause_event = find_event_in_timeline(target_tl, req.cause_event_id);
                if (cause_event) {
                    event->causal_dependency = cause_event;
                    event_get(cause_event);
                }
            }
        }
    }
}
```

Consequently, when the close handler attempts to release those dependencies, it enters an infinite loop because `->causal_dependency` [2] points to the event itself.

``` c
static int paradox_engine_release(struct inode *inode, struct file *filp) {
    struct paradox_session_data *session = filp->private_data;
    struct timeline *tl, *tmp_tl;
    struct temporal_event *event, *tmp_event;

    list_for_each_entry(tl, &session->all_timelines, session_node) {
        list_for_each_entry_safe(event, tmp_event, &tl->events_head, timeline_node) {
            
            struct temporal_event *cause = event->causal_dependency;
            list_del(&event->timeline_node);
            while (cause) {
                struct temporal_event *next_in_chain = cause->causal_dependency; // [2]
                event_put(cause);
                cause = next_in_chain;
            }
            // [...]
            event_put(event);
        }
    }
    // [...]
}
```

The `event_put()` function decrements an event’s reference count and frees it once the count drops to zero. Conversely, `event_get()` is invoked by operations that hold a pointer to the event object.

``` c
static void event_get(struct temporal_event *event) {
    if (event)
        refcount_inc(&event->causal_weight);
}

static void event_put(struct temporal_event *event) {
    if (event && refcount_dec_and_test(&event->causal_weight))
        event_erase_from_reality(event);
}

static void event_erase_from_reality(struct temporal_event *event) {
    kfree(event);
}
```

So, we can have the event referenced by other objects and then exploit the self-referencing behavior to trigger its release within the infinite loop. This gives us a UAF primitive on the event object.

Moreover, when `refcount_dec_and_test()` is called on a freed event whose refcount has already dropped to zero and been released, only the refcount field is overwritten with a magic number [3], which appears harmless.

``` c
static inline __must_check bool refcount_dec_and_test(refcount_t *r)
{
    return __refcount_dec_and_test(r, NULL); // <---------------
}

static inline __must_check bool __refcount_dec_and_test(refcount_t *r, int *oldp)
{
    return __refcount_sub_and_test(1, r, oldp); // <---------------
}

static inline __must_check __signed_wrap
bool __refcount_sub_and_test(int i, refcount_t *r, int *oldp)
{
    int old = atomic_fetch_sub_release(i, &r->refs);

    if (oldp)
        *oldp = old;

    if (old > 0 && old == i) {
        smp_acquire__after_ctrl_dep();
        return true;
    }

    if (unlikely(old <= 0 || old - i < 0))
        refcount_warn_saturate(r, REFCOUNT_SUB_UAF); // [3]

    return false;
}
```

## 3. Exploitation

### 3.1. First Attempt

To exploit it, my first thought is to make the UAF object persistent, meaning we can break out of the infinite loop and exit the release handler.

I reclaimed the UAF event as another event object. Because the allocation flag contains `__GFP_ZERO` [1], the `->causal_dependency` of the newly created event object will be set to NULL, which breaks the loop. After that, the `event_put()` call outside the loop may free the reclaimed event object, allowing us to obtain a freed event in the list [2].

``` c
static long paradox_engine_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    // [...]
    switch (cmd) {
        case PARADOX_CREATE_EVENT:
        {
            struct temporal_event *event = kmem_cache_alloc(temporal_event_cache, GFP_KERNEL|__GFP_ZERO); // [1]
            // [...]
            event->event_id = atomic64_fetch_add(1, &target_tl->next_event_id);
            refcount_set(&event->causal_weight, 1);
            // [...]
            list_add_tail(&event->timeline_node, &target_tl->events_head); // [2]
            // [...]
        }
    }
    // [...]
}
```

The ioctl command `PARADOX_CREATE_TIMELINE` searches for the event [3] and updates the event’s refcount [4].

``` c
static long paradox_engine_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    // [...]
    switch (cmd) {
        case PARADOX_CREATE_TIMELINE:
        {
            // [...]
            struct temporal_event *cause_event = NULL;
            list_for_each_entry(tmp_tl, &session->all_timelines, session_node) {
                if(tmp_tl->timeline_id == req.cause_timeline_id) {
                    cause_event = find_event_in_timeline(tmp_tl, req.cause_event_id); // [3]
                    if(cause_event) break;
                }
            }
            // [...]

            struct timeline *new_tl = kzalloc(sizeof(*new_tl), GFP_KERNEL);
            new_tl->caused_by_event = cause_event;
            event_get(cause_event); // [4]
            // [...]
        }
    }
    // [...]
}
```

The `find_event_in_timeline()` function iterates through the linked list and finds the event with the corresponding ID [5].

``` c
static struct temporal_event* find_event_in_timeline(struct timeline *tl, u64 event_id) {
    struct temporal_event *ev;
    if (!tl) return NULL;
    list_for_each_entry(ev, &tl->events_head, timeline_node) {
        if (ev->event_id == event_id) return ev; // [5]
    }
    return NULL;
}
```

So, if we cross-cache the event into other structures, we obtain an **increment-by-one primitive** that can be triggered multiple times. However, we must know the `->event_id` value of the reclaimed object, and this value cannot be zero due to the default event; otherwise, the victim event will not be found, leading to a kernel panic caused by the corrupted linked list.

I target the `page` field of `pipe_buffer` because, once the exploit succeeds, the `page` pointer will overlap with another `page`, allowing me to construct a page UAF primitive. Although object alignment issues make the exploit unreliable, I temporarily assumed the layout behaves as expected (a low success rate is acceptable in CTF 😝).

``` c
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
};
```

If the cross-cache attempt succeeds, the heap layout should look like:

```
...

                        pipe_buffer[0]->page
0xffff888007645840:     0xffffea0000180200            0x0000100000000000
0xffff888007645850:     0xffffffff82c6e280            0x0000000000000010

                        pipe_buffer[0]->private       pipe_buffer[1]->page
0xffff888007645860:     0x0000000000000000            0xffffea0000180240
0xffff888007645870:     0x0000100000000000            0xffffffff82c6e280
0xffff888007645880:     0x0000000000000010            0x0000000000000000

...
```

Unfortunately, when retrieving the `pipe_buffer[1]->page`, the `pipe_buffer[0]->private` is always zero, which collides with the ID of the default event. Since this value is uncontrollable by the user, we cannot decrement the `page` pointer.

I spent some more time searching for other suitable objects but failed. As a result, I went back to review the kernel module again, hoping to gain new ideas from it.

### 3.2. Second Attempt

Soon after, I noticed that the end of the release handler also operates on the event object, but this time it provides a **decrement-by-one primitive** [1]. Unlike the increment case, this primitive does not require knowing the event ID. However, we still need to perform cross-cache and reclaim the memory as a `pipe_buffer` in the window between the infinite loop freeing the object and the `event_put()` call during the timeline iteration [2].

``` c
static int paradox_engine_release(struct inode *inode, struct file *filp) {
    // [...]
    list_for_each_entry_safe(tl, tmp_tl, &session->all_timelines, session_node) { // [2]
        list_del(&tl->session_node);
        
        if (tl->caused_by_event)
            event_put(tl->caused_by_event); // [1]
        kfree(tl);
    }

    kfree(session);
    return 0;
}
```

To extend the time window, I inserted many timelines bound to another event before inserting the timelines bound to the UAF event. This makes the iteration take longer, and by the time it reaches the crafted timelines, we have already reclaimed the UAF event as `pipe_buffer` objects.

If the `page` pointer is successfully decremented, it will point to the `page` held by another `pipe_buffer`. At this point, we can read a page to place the victim `page` into `pipe->tmp_page` within the `anon_pipe_buf_release()` function [3]. Then, by reading all the data, we free the victim `page` — which is still referenced by another `pipe_buffer` — back to the buddy system [4].

``` c
static void anon_pipe_buf_release(struct pipe_inode_info *pipe,
                  struct pipe_buffer *buf)
{
    struct page *page = buf->page;

    if (page_count(page) == 1 && !pipe->tmp_page)
        pipe->tmp_page = page; // [3]
    else
        put_page(page); // [4]
}
```

This `page` can later be reused by writing data into the pipe [5].

``` c
static ssize_t
pipe_write(struct kiocb *iocb, struct iov_iter *from)
{
    // [...]
    for (;;) {
        // [...]
        if (!pipe_full(head, pipe->tail, pipe->max_usage)) {
            unsigned int mask = pipe->ring_size - 1;
            struct pipe_buffer *buf;
            struct page *page = pipe->tmp_page;
            int copied;

            if (!page) {
                page = alloc_page(GFP_HIGHUSER | __GFP_ACCOUNT);
                // [...]
            }

            pipe->head = head + 1;
            // [...]
            buf = &pipe->bufs[head & mask];
            buf->page = page; // [5]
            buf->ops = &anon_pipe_buf_ops;
            buf->offset = 0;
            buf->len = 0;
            // [...]
        }
    }
}
```

After constructing a page UAF primitive, I chose to spray `struct file` objects to reclaim the UAF page by repeatedly opening `"/bin/busybox"`. The `file` structure contains the `f_mode` field at the beginning [6], which determines whether a file is mappable via `SYS_mmap`.

``` c
struct file {
    atomic_long_t f_count;
    spinlock_t f_lock;
    fmode_t f_mode; // [6]
    // [...]
};
```

By overwriting `f_mode` to set the `FMODE_WRITE` flag, we can hijack the contents of `"/bin/busybox"`. I then overwrote the `main()` function of `"/bin/busybox"` to read `"/flag"` for me, and when the `poweroff` command [7] was executed in the `"/init"` script, the flag was displayed in the terminal!

``` bash
# [...]
setsid cttyhack setuidgid 1000 sh
poweroff -f # [7]
```

The full exploit can be found [here](/assets/starlabs-summer-pwnables-linux-kernel-exp.c).

### 3.3. Stablility

There are several reasons why my exploit is very unreliable:

1. The size of the event (`struct temporal_event`) is 0x70, while the target struct `pipe_buffer` resides in `kmalloc-cg-256`. When attempting to overwrite the page, we may end up writing into unused memory (causing no effect) or into the wrong fields, which can trigger a kernel panic.
2. The release/reclaim operations have execution order issues with both the infinite loop and the timeline iteration. However, I was unable to make the execution flow deterministic.

Pretty bad… but it works xD.

### 3.4. Intended Solution

After solving it, I came across the hints provided in the [STAR Labs’ LinkedIn post](https://www.linkedin.com/posts/starlabs-sg_challenge-002-feeling-stuck-time-for-activity-7364558318964543488-GcKd) and was surprised, because the official solution turned out to be very simple!

Once we cross-cache and reclaim the page, we can overwrite the refcount of the UAF event to 1, causing the UAF object to be freed. While the UAF event is being freed within an active page, the `kfree()` implementation handles it correctly!

Let’s take a look at `kfree()`. If the object is located in a slab, `slab_free()` is called to release the object [1]; otherwise, `free_large_kmalloc()` is invoked to release a page that was directly allocated from the buddy system.

``` c
void kfree(const void *object)
{
    struct folio *folio;
    struct slab *slab;
    struct kmem_cache *s;
    void *x = (void *)object;

    trace_kfree(_RET_IP_, object);

    if (unlikely(ZERO_OR_NULL_PTR(object)))
        return;

    folio = virt_to_folio(object);
    if (unlikely(!folio_test_slab(folio))) {
        free_large_kmalloc(folio, (void *)object); // [2]
        return;
    }

    // ==== [1] ====
    slab = folio_slab(folio);
    s = slab->slab_cache;
    slab_free(s, slab, x, _RET_IP_);
}
```

The `free_large_kmalloc()` function does not perform any validation on the given address (`object`); it simply calls `folio_put()` [3] to release the page.

``` c
static void free_large_kmalloc(struct folio *folio, void *object)
{
    unsigned int order = folio_order(folio);

    // [...]
    folio_put(folio); // [3]
}
```

With this feature, we can construct an easier and more stable page UAF primitive — awesome!

## 4. Conclusion

Linux kernel CTF challenges are still fun for me, and I hope I can keep my passion for them for many years to come :).
