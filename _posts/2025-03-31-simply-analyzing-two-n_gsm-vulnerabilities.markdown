---
layout: post
title:  "Simply Analyzing Two N_GSM Vulnerabilities"
categories: linux
---

The repo [Linux kernel exploitation](https://github.com/xairy/linux-kernel-exploitation) contains a bunch of great resources for learning about Linux kernel vulnerabilities. Among them, the tty and `N_GSM` subsystems stood out to me - mostly because I'm not too familiar with them. To get a better grasp, I checked out two `N_GSM` vulnerability write-ups shared by @roddux, which helped me dive into how the tty subsystem is actually implemented.

This blog post is mainly a note on my exploration process. It focuses on how the tty subsystem is initialized and how it works in general. I won't go too deep into any specific vulnerabilities or exploitation techniques here.

## 1. Introduction

## 1.1. Initializing the devpts File System

The `init_devpts_fs()` function is responsible for initializing the `devpts` file system during boot. As part of the setup, it also creates a special file called `ptmx` [1].

``` c
static int __init init_devpts_fs(void)
{
    int err = register_filesystem(&devpts_fs_type);
    // [...]
}

static struct file_system_type devpts_fs_type = {
    .name      =  "devpts",
    // [...]
};

static struct dentry *devpts_mount(struct file_system_type *fs_type,
    int flags, const char *dev_name, void *data)
{
    return mount_nodev(fs_type, flags, data, devpts_fill_super);
}

static int
devpts_fill_super(struct super_block *s, void *data, int silent)
{
    // [...]
    error = mknod_ptmx(s);
    // .[...]
}

static int mknod_ptmx(struct super_block *sb)
{
    dentry = d_alloc_name(root, "ptmx"); // [1]
    // [...]
    inode = new_inode(sb);
    // [...]
    d_add(dentry, inode);
    // [...]
}
```

### 1.2. Initializing pty

Another important init function is `unix98_pty_init()`, which sets up the pseudo terminal (pty) driver. This function also registers a device with the name `"/dev/ptmx"` [1] - though in reality, it's just an alias for the `/dev/ptmx` device created earlier.

``` c
static int __init pty_init(void)
{
    // [...]
    unix98_pty_init(); // <----------------
    return 0;
}

// drivers/tty/pty
static struct tty_driver *ptm_driver;
static struct tty_driver *pts_driver;
static void __init unix98_pty_init(void)
{
    ptm_driver = tty_alloc_driver(/*...*/);
    pts_driver = tty_alloc_driver(/*...*/);

    ptm_driver->driver_name = "pty_master";
    // [...]
    ptm_driver->name = "ptm";
    tty_set_operations(ptm_driver, &ptm_unix98_ops);

    pts_driver->driver_name = "pty_slave";
    // [...]
    pts_driver->name = "pts";
    tty_set_operations(pts_driver, &pty_unix98_ops);

    // [...]
    tty_register_driver(ptm_driver);
    tty_register_driver(pts_driver);

    // [...]
    tty_default_fops(&ptmx_fops);
    ptmx_fops.open = ptmx_open; // [2]

    cdev_init(&ptmx_cdev, &ptmx_fops);
    cdev_add(&ptmx_cdev, MKDEV(TTYAUX_MAJOR, 2), 1);
    register_chrdev_region(MKDEV(TTYAUX_MAJOR, 2), 1, "/dev/ptmx"); // [1]
    // [...]
}
```

The `tty_default_fops()` function sets up the file operations using `tty_fops`, but the open handler gets replaced with `ptmx_open()` afterwards [2].

``` c
void tty_default_fops(struct file_operations *fops)
{
    *fops = tty_fops;
}

static const struct file_operations tty_fops = {
    // [...]
};
```

When `tty_register_driver()` is called, it registers the tty character device into a mapping table called `cdev_map` [3]. This allows the system to later look up the `struct cdev` directly from the map when needed.

``` c
int tty_register_driver(struct tty_driver *driver)
{
    // [...]
    if (driver->flags & TTY_DRIVER_DYNAMIC_ALLOC) {
        error = tty_cdev_add(driver, dev, 0, driver->num); // <----------------
        // [...]
    }
}

static int tty_cdev_add(struct tty_driver *driver, dev_t dev,
        unsigned int index, unsigned int count)
{
    int err;
    driver->cdevs[index] = cdev_alloc();
    driver->cdevs[index]->ops = &tty_fops;
    // [...]
    err = cdev_add(driver->cdevs[index], dev, count); // <----------------
    return err;
}

int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
    p->dev = dev;
    p->count = count;
    kobj_map(cdev_map, dev, count, NULL, // [3]
             exact_match, exact_lock, p);
    kobject_get(p->kobj.parent);
    return 0;
}
```

## 1.3. Opening /dev/ptmx

To use a pty, you first need to open `/dev/ptmx` or `/dev/pts/ptmx` to get the pty master. When you do this, the ptmx open handler creates a corresponding pty slave inode, allowing the master and slave ends to communicate through standard file operations.

When opening files under the `/dev/` directory, the kernel runs the `init_special_inode()` function, which initializes the inode's file operations to `&def_chr_fops` [1].

``` c
void init_special_inode(struct inode *inode, umode_t mode, dev_t rdev)
{
    inode->i_mode = mode;
    if (S_ISCHR(mode)) {
        inode->i_fop = &def_chr_fops; // [1]
        // [...]
    }
    // [...]
}
        
const struct file_operations def_chr_fops = {
    .open = chrdev_open, // [2]
    // [...]
};
```

Next, the kernel calls the `chrdev_open()` function [2], which tries to get the inode's associated `struct cdev` [3] and then calls the character device's actual open handler [4]. But if the inode isn't already bound to a character device [5], it looks up the device in the `cdev_map` and binds it dynamically [6].

``` c
static int chrdev_open(struct inode *inode, struct file *filp)
{
    struct cdev *p;

    // [...]
    p = inode->i_cdev; // [3]
    if (!p) { // [5]
        struct kobject *kobj;
        int idx;
        // [...]
        kobj = kobj_lookup(cdev_map, inode->i_rdev, &idx);
        new = container_of(kobj, struct cdev, kobj);
        // [...]
        inode->i_cdev = p = new; // [6]
        list_add(&inode->i_devices, &p->list);
        // [...]
    } 
    
    // [...]
    fops = fops_get(p->ops);

    // [...]
    replace_fops(filp, fops);
    if (filp->f_op->open) {
        ret = filp->f_op->open(inode, filp); // [4]
    }
    // [...]
}
```

If the file being opened is `/dev/ptmx`, then `chrdev_open()` ends up using `&ptmx_fops` as the file operations, which means the open handler will be `ptmx_open()`.

The `ptmx_open()` function not only sets up the tty-related structures, but also calls `devpts_pty_new()` [7] to create a new file (inode) under `/dev/pts/`.

``` c
static int ptmx_open(struct inode *inode, struct file *filp)
{
    struct pts_fs_info *fsi;
    struct tty_struct *tty;
    
    // [...]
    retval = tty_alloc_file(filp); // create `struct tty_file_private` for file->private
    fsi = devpts_acquire(filp); // get "/dev/pts" info
    index = devpts_new_index(fsi); // allocate an unused index
    tty = tty_init_dev(ptm_driver, index); // install a tty entry
    dentry = devpts_pty_new(fsi, index, tty->link); // [7], create a new inode in /dev/pts/
    retval = ptm_driver->ops->open(tty, filp); // call `pty_open()`
    // [...]
}
```

The new inode will appear in `/dev/pts/` with the filename equal to the allocated index [7]. During this process, `init_special_inode()` is also called again [8] to set up file operations for the slave side.

``` c
struct dentry *devpts_pty_new(struct pts_fs_info *fsi, int index, void *priv /* tty->link */)
{
    struct super_block *sb = fsi->sb;
    struct inode *inode;
    // [...]
    root = sb->s_root;
    inode = new_inode(sb); // [7]
    init_special_inode(inode, S_IFCHR|opts->mode, MKDEV(UNIX98_PTY_SLAVE_MAJOR, index) /* rdev */); // [8]
    dentry = d_alloc_name(root, s);
    dentry->d_fsdata = priv;
    // [...]
}
```

In the end, the user space process receives a fd to the pty master. If it wants to communicate with the pty slave, it needs to open the file the kernel created: `/dev/pts/{index}`.

### 1.4. Opening /dev/pts/0

The flow for opening `/dev/pts/0` is mostly the same as opening `/dev/ptmx`, with one key difference: the final chrdev looked up in the device map is different. As a result, the kernel ends up calling the open handler from `tty_fops`, which is `tty_open()` [1].

``` c
static const struct file_operations tty_fops = {
    // [...]
    .open = tty_open, // [1]
    // [...]
};
```

Inside `tty_open()`, the tty object is initialized, and then the tty driver’s open handler gets called - in this case, `pty_open()`. However, `pty_open()` doesn't do much beyond setting a few internal flags.

``` c
static int tty_open(struct inode *inode, struct file *filp)
{
    // [...]
    retval = tty_alloc_file(filp);
    
    // [...]
    tty_add_file(tty, filp);
    
    // [...]
    if (tty->ops->open)
        retval = tty->ops->open(tty, filp); // [2], `pty_open()`
    
    // [...]
}
```

### 1.5. GSM tty Driver

If the kernel is built with `CONFIG_N_GSM=y`, then tty objects can make use of the **GSM MUX line discipline**.

The GSM MUX line discipline is initialized via `gsm_init()`, which sets the driver name to `"gsmtty"` [1] and registers the GSM tty driver [2]. In addition, because tty drivers have a discipline-specific ops, GSM also registers its own operations - `tty_ldisc_packet` [3].

``` c
static int __init gsm_init(void)
{
    // [...]
    int status = tty_register_ldisc(&tty_ldisc_packet); // [3]
    // [...]
    gsm_tty_driver = tty_alloc_driver(GSM_TTY_MINORS, TTY_DRIVER_REAL_RAW |
            TTY_DRIVER_DYNAMIC_DEV | TTY_DRIVER_HARDWARE_BREAK);
    gsm_tty_driver->driver_name    = "gsmtty"; // [1]
    tty_set_operations(gsm_tty_driver, &gsmtty_ops); // [2]
    // [...]
}

static struct tty_ldisc_ops tty_ldisc_packet = {
    // [...]
    .num   =  N_GSM0710 /* 21 */,
    .name  =  "n_gsm",
    .ioctl =  gsmld_ioctl,
    // [...]
};
```

GSM isn't the only line discipline available - others like PPP also exist. If you want to check which line disciplines are registered on your system, you can inspect the global `tty_ldiscs[]` array and see which indices are registered.

``` c
#define N_TTY        0
// [...]
#define NR_LDISCS    31

static struct tty_ldisc_ops *tty_ldiscs[NR_LDISCS];
```

When a tty object is initialized, the kernel assigns it a default line discipline using the `tty_ldisc_init()` function. By default, it uses `N_TTY` (0), which corresponds to the classic `n_tty_ops`.

``` c
/*
ptmx_open
=> tty_init_dev
==> alloc_tty_struct
===> tty_ldisc_init
*/
int tty_ldisc_init(struct tty_struct *tty)
{
    struct tty_ldisc *ld = tty_ldisc_get(tty, N_TTY);
    tty->ldisc = ld;
    return 0;
}
```

At runtime, the line discipline of a tty object can be changed dynamically using the `ioctl(TIOCSETD, &num)` system call.

``` c
long tty_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    // [...]
    switch (cmd) {
    case TIOCSETD:
        return tiocsetd(tty, p);
    }
    // [...]
}

static int tiocsetd(struct tty_struct *tty, int __user *p)
{
    int disc;
    int ret;

    // [...]
    ret = tty_set_ldisc(tty, disc);
    return ret;
}
```

The number value needs to match the line discipline number. For example, to switch to `GSM`, you'd pass in `N_GSM0710` (21). Eventually, `tty_ldisc_open()` will be called to run the line discipline's open handler - in the case of GSM, that's `gsmld_open()` [4].

``` c
int tty_set_ldisc(struct tty_struct *tty, int disc)
{
    // [...]
    new_ldisc = tty_ldisc_get(tty, disc)
    tty->ldisc = new_ldisc;
    
    // [...]
    retval = tty_ldisc_open(tty, new_ldisc); // <----------------
    
    // [...]
}

static int tty_ldisc_open(struct tty_struct *tty, struct tty_ldisc *ld)
{
    // [...]
    if (ld->ops->open) {
        ret = ld->ops->open(tty); // [4], `gsmld_open()`
        // [...]
    }
    // [...]
}
```

However, while going through this, I also found that recent kernels require `CAP_NET_ADMIN` privileges to use the GSM line discipline, and this restriction was added in a [commit](https://github.com/gregkh/linux/commit/67c37756898a5a6b2941a13ae7260c89b54e0d88) from August 4, 2023.

``` c
static int gsmld_open(struct tty_struct *tty)
{
    struct gsm_mux *gsm;

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;
    
    // [...]
}
```

## 2. CVE-2024-36016: tty: n_gsm: fix possible out-of-bounds in gsm0_receive()
> Reference:
> 1. https://github.com/roddux/germy
> 2. https://ubuntu.com/security/CVE-2024-36016
> 3. https://web.git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=47388e807f85948eefc403a8a5fdc5b406a65d5a

### 2.1. Root Cause Analysis

The GSM MUX supports two types of encoding: `BASIC` and `ADV` (advanced). You can switch between them using the `ioctl(GSMIOC_SETCONF)` call [1]. When `gsm_config()` sees that the GSM state is marked as "dead", it calls `gsm_activate_mux()` to update the receive handler [2].

``` c
enum gsm_encoding {
    GSM_BASIC_OPT,
    GSM_ADV_OPT,
};

static int gsmld_ioctl(struct tty_struct *tty, unsigned int cmd,
               unsigned long arg)
{
    switch (cmd) {
    // [...]
    case GSMIOC_SETCONF:
        copy_from_user(&c, (void __user *)arg, sizeof(c));
        return gsm_config(gsm, &c); // <----------------
    // [...]
    }
}

static int gsm_config(struct gsm_mux *gsm, struct gsm_config *c)
{
    // [...]
    gsm->encoding = c->encapsulation ? GSM_ADV_OPT : GSM_BASIC_OPT; // [1]
    // [...]
    if (gsm->dead) {
        int ret = gsm_activate_mux(gsm); // [2]
        // [...]
    }
    return 0;
}

static int gsm_activate_mux(struct gsm_mux *gsm)
{
    // [...]
    if (gsm->encoding == GSM_BASIC_OPT)
        gsm->receive = gsm0_receive;
    else
        gsm->receive = gsm1_receive;
    // [...]
}
```

When data is received on a tty, the kernel calls the line discipline's `receive_buf` handler [3], which then invokes the corresponding encoding handler (`gsm0_receive` or `gsm1_receive`) [4].

``` c
static struct tty_ldisc_ops tty_ldisc_packet = {
    // [...]
    .name         = "n_gsm",
    // [...]
    .receive_buf  = gsmld_receive_buf, // [3]
    // [...]
};

static void gsmld_receive_buf(struct tty_struct *tty, const u8 *cp,
                  const u8 *fp, size_t count)
{
    struct gsm_mux *gsm = tty->disc_data;
    char flags = TTY_NORMAL;

    for (; count; count--, cp++) {
        if (fp)
            flags = *fp++;
        switch (flags) {
        case TTY_NORMAL:
            if (gsm->receive)
                gsm->receive(gsm, *cp); // [4]
            break;
        // [...]
        }
    }
    // [...]
}
```

Here's the vulnerable code in order kernel.

When switching modes, the `gsm->state` field isn't reset. So if the current state is `GSM_DATA` before the switch, it stays in that state even after switching modes.

The problem is that both receive handlers (`gsm0_receive` for `BASIC` and `gsm1_receive` for `ADV`) share the same internal buffer, but **perform different bounds checks**. Notably, `gsm1_receive()` uses an equal-to check for `gsm->count` and `gsm->len` [5].

``` c
static void gsm0_receive(struct gsm_mux *gsm, u8 c)
{
    switch (gsm->state) {
    // [...]
    case GSM_DATA:
        gsm->buf[gsm->count++] = c;
        if (gsm->count == gsm->len) { // [5]
            if ((gsm->control & ~PF) != UIH) {
                gsm->fcs = gsm_fcs_add_block(gsm->fcs, gsm->buf,
                                 gsm->count);
            }
            gsm->state = GSM_FCS; // [7]
        }
        break;
    // [...]
    }
}

static void gsm1_receive(struct gsm_mux *gsm, u8 c)
{
    switch (gsm->state) {
    // [...]
    case GSM_DATA:
        if (gsm->count > gsm->mru) { // [6]
            // [...]
            gsm->bad_size++;
        } else
            gsm->buf[gsm->count++] = c;
        break;
    // [...]
    }
}
```

An attacker can abuse this by first switching to `ADV` mode and crafting input that causes `gsm->count` to exceed `gsm->len`. Then, when switching back to `BASIC` mode, `gsm0_receive()` won't enter the state transition block [7], leaving the state machine in an inconsistent state and allowing an OOB write.

### 2.2. Exploitation

For full details, refer to the [original writeup](https://github.com/roddux/germy) - this section is just a high-level summary.

This vulnerability enables an OOB write with a controllable and unbounded offset. The OOB write occurs in the GSM buffer (`gsm->buf`), which is allocated from the `kmalloc-2k` slab. The author's goal is to overflow a neighboring `struct netlink_sock`, which is also allocated from `kmalloc-2k`.

The exploit starts by spraying a large number of `netlink_sock` objects, freeing some of them, and immediately triggering GSM to allocate its buffer. This increases the chance that `gsm->buf` ends up adjacent to a `netlink_sock`. After triggering the bug, the attacker can overwrite `netlink_sock->sk.sk_family` and use the syscall `sys_getsockopt(SO_DOMAIN)` to detect whether the overflow succeeded and which object was hit.

Next, the attacker overflows `netlink_sock->sk.sk_buff_head`. By combining this with `poll()`, they can leak the address of `gsm->buf` via a side channel - giving them a kernel heap address.

With the heap address in hand, the attacker proceeds to overflow `netlink_sock->sk.skc_net`, making it point to `netlink_sock->sk.sk_prot_creator`, which lives on the same socket object. Then, calling `sys_getsockopt(SO_NETNS_COOKIE)` returns the value of `skc_net->cookie`, leaking a kernel text address.

The same method can be used to leak additional pointers, such as `sk->socket`, `sk->socket->file`, and `sk->socket->file->f_cred`.

Finally, the attacker overwrites `netlink_sock->sk.sk_prot`, gaining control over the socket's function table. When `sys_getsockopt(SO_KEEPALIVE)` is called, it ends up executing `bpf_prog_free_id()`, which can be abused to set `cred->uid` to 0. After that, calling `setuid(0)` in user space gives the attacker full root privileges.

## 3. Race Condition in N_GSM
> Reference:
> 1. https://github.com/roddux/ixode
> 2. https://x.com/roddux/status/1826212931358343351

### 3.1. Creating a GSM DLCI

You can configure a GSM tty's DLCI (Data Link Connection Identifier) using the `ioctl(GSMIOC_SETCONF_DLCI)` call [1]. Each GSM tty object can register up to `NUM_DLCI` (64) DLCIs [2].

``` c
static int gsmld_ioctl(struct tty_struct *tty, unsigned int cmd,
               unsigned long arg)
{
    // [...]
    switch (cmd) {
    case GSMIOC_SETCONF_DLCI:
        copy_from_user(&dc, (void __user *)arg, sizeof(dc));
        // [...]
        addr = array_index_nospec(dc.channel, NUM_DLCI); // [2]
        if (!dlci) {
            dlci = gsm_dlci_alloc(gsm, addr);
        }
        // [...]
        return gsm_dlci_config(dlci, &dc, 0); // [1]
    }
}
```

The `gsm_dlci_alloc()` function allocates and initializes a new DLCI object, and registers it in the `gsm->dlci[]` array [3].

``` c
static struct gsm_dlci *gsm_dlci_alloc(struct gsm_mux *gsm, int addr)
{
    struct gsm_dlci *dlci = kzalloc(sizeof(struct gsm_dlci), GFP_ATOMIC);
    
    // [...]
    timer_setup(&dlci->t1, gsm_dlci_t1, 0);
    tty_port_init(&dlci->port);
    dlci->port.ops = &gsm_port_ops;

    // [...]
    dlci->gsm = gsm;

    // [...]
    dlci->state = DLCI_CLOSED;
    
    // [...]
    gsm->dlci[addr] = dlci; // [3]
    return dlci;
}
```

After allocation, `gsm_dlci_config()` is used to set the runtime parameters of the DLCI object based on user parameters. By default, a new DLCI starts in the `DLCI_CLOSED` state. If the DLCI needs to be opened, the function `gsm_dlci_begin_open()` is called to transition the state to `DLCI_OPENING` [4], and also schedules a timer [5].

``` c
static int gsm_dlci_config(struct gsm_dlci *dlci, struct gsm_dlci_config *dc, int open)
{
    // [...]
    if (need_open) {
        if (gsm->initiator)
            gsm_dlci_begin_open(dlci); // <----------------
        // [...]
    }
}

static void gsm_dlci_begin_open(struct gsm_dlci *dlci)
{
    // [...]
    switch (dlci->state) {
    // [...]
    case DLCI_CLOSING:
        if (!need_pn) {
            dlci->state = DLCI_OPENING; // [4]
            // [...]
        }
        // [...]
        mod_timer(&dlci->t1, jiffies + gsm->t1 * HZ / 100); // [5]
        break;
    // [...]
    }
}
```

### 3.2. Releasing a GSM DLCI

When a GSM object is being closed, the kernel calls `gsm_cleanup_mux()` to clean up related resources. This includes releasing any registered DLCI objects via `gsm_dlci_release()` [1].

``` c
static struct tty_ldisc_ops tty_ldisc_packet = {
    // [...]
    .close = gsmld_close, // <----------------
    // [...]
}

static void gsmld_close(struct tty_struct *tty)
{
    struct gsm_mux *gsm = tty->disc_data;
    gsm_cleanup_mux(gsm, false); // <----------------
    // [...]
}

static void gsm_cleanup_mux(struct gsm_mux *gsm, bool disc)
{
    int i;
    struct gsm_dlci *dlci;

    // [...]
    for (i = NUM_DLCI - 1; i >= 0; i--)
        if (gsm->dlci[i])
            gsm_dlci_release(gsm->dlci[i]); // [1]
    // [...]
}
```

The `gsm_dlci_release()` function internally calls `tty_port_destructor()` [2] to clean up and free the DLCI object.

``` c
static void gsm_dlci_release(struct gsm_dlci *dlci)
{
    // [...]
    dlci->state = DLCI_CLOSED;
    dlci_put(dlci); // <----------------
}

static inline void dlci_put(struct gsm_dlci *dlci)
{
    tty_port_put(&dlci->port); // <----------------
}

void tty_port_put(struct tty_port *port)
{
    if (port)
        kref_put(&port->kref, tty_port_destructor); // [2]
}
```

During allocation in `gsm_dlci_alloc()`, the port ops was initialized with `gsm_port_ops`, so the cleanup path calls `gsm_dlci_free()` as the final destructor [3].

``` c
static void tty_port_destructor(struct kref *kref)
{
    struct tty_port *port = container_of(kref, struct tty_port, kref);
    // [..]
    if (port->ops && port->ops->destruct)
        port->ops->destruct(port); // [3], call `gsm_dlci_free()`
    // [..]
}
```

The function `gsm_dlci_free()` ensures the timer has completed before freeing the object. It calls `timer_shutdown_sync()` to wait for the timer handler to finish [4], then frees the DLCI structure [5].

``` c
static void gsm_dlci_free(struct tty_port *port)
{
    struct gsm_dlci *dlci = container_of(port, struct gsm_dlci, port);

    timer_shutdown_sync(&dlci->t1); // [4]
    dlci->gsm->dlci[dlci->addr] = NULL;
    // [...]
    kfree(dlci); // [5]
}
```

### 3.3. Timer

The DLCI timer handler, `gsm_dlci_t1()`, performs different actions depending on the current state of the DLCI object. These actions may include retransmitting control frames or triggering a shutdown.

``` c
static void gsm_dlci_t1(struct timer_list *t)
{
    struct gsm_mux *gsm = dlci->gsm;
    // [...]
    switch (dlci->state) {
    // [...]
    }
}
```

### 3.4. Vulnerability

The function `gsmld_ioctl()` **does not use a lock when initializing a DLCI object**. This opens up a **race condition** where two threads could simultaneously check for the absence of a DLCI at a specific channel, and both end up calling `gsm_dlci_alloc()` to allocate one.

``` c
static int gsmld_ioctl(struct tty_struct *tty, unsigned int cmd,
               unsigned long arg)
{
    // [...]
    switch (cmd) {
    case GSMIOC_SETCONF_DLCI:
        addr = array_index_nospec(dc.channel, NUM_DLCI);
        if (!dlci) {
            dlci = gsm_dlci_alloc(gsm, addr);
        }
        // [...]
    }
}
```

The GSM object manages its DLCIs through the `gsm->dlci[]` array [1], while each DLCI object holds a reference to the parent GSM object via its `gsm` field [2]. However, when assigning `dlci->gsm`, there's no increase in the refcount, meaning the DLCI **holds a raw pointer to the GSM object without guaranteeing its lifetime**.

If this race occurs, only one of the DLCI objects will actually be registered in `gsm->dlci[addr]`. The other DLCI will be left unmanaged by the GSM object.

``` c
static struct gsm_dlci *gsm_dlci_alloc(struct gsm_mux *gsm, int addr)
{
    // [...]
    dlci->gsm = gsm; // [2]
    
    // [...]
    gsm->dlci[addr] = dlci; // [1]
    
    return dlci;
}
```

Later, when the GSM tty is being closed, `gsm_cleanup_mux()` iterates through all entries in `gsm->dlci[]` [3], ensuring each DLCI is properly released. That includes shutting down any active timers [4] and freeing the memory [5].

``` c
static void gsm_cleanup_mux(struct gsm_mux *gsm, bool disc)
{
    int i;
    struct gsm_dlci *dlci;

    // [...]
    for (i = NUM_DLCI - 1; i >= 0; i--) // [3]
        if (gsm->dlci[i])
            gsm_dlci_release(gsm->dlci[i]);
    
    // [...]
}

static void gsm_dlci_free(struct tty_port *port)
{
    struct gsm_dlci *dlci = container_of(port, struct gsm_dlci, port);

    timer_shutdown_sync(&dlci->t1); // [4]
    // [...]
    kfree(dlci); // [5]
}
```

After that, the GSM object itself will be released [6] by `gsmld_close()`, which is the function that originally called `gsm_cleanup_mux()`.

``` c
static void gsmld_close(struct tty_struct *tty)
{
    struct gsm_mux *gsm = tty->disc_data;
    // [...]
    gsm_cleanup_mux(gsm, false);
    // [...]
    mux_put(gsm); // [6]
}
```

However, the unmanaged DLCI object - the one that wasn't stored in `gsm->dlci[]` due to the race - still has a reference to the GSM object via `dlci->gsm`. If its timer fires after the GSM object has already been freed, the timer handler will access freed memory, **resulting in an UAF**.

## 4. Others

Besides the two CVEs discussed earlier, N_GSM has had several other similar vulnerabilities. For example, [CVE-2024-50073](https://web.git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=9462f4ca56e7d2430fdb6dcc8498244acbfc4489), or even a [0day analysis](https://github.com/fff-vr/n_gsm_exploit/tree/master) published by @fffvr, as well as the public exploit repo [ExploitGSM](https://github.com/YuriiCrimson/ExploitGSM).

Although there may still be bugs in this subsystem, researchers are not expected to explore it further, as it isn't accessible by default without `CAP_NET_ADMIN`.