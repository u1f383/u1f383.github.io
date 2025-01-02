---
layout: post
title:  "Troubleshooting"
categories: cheatsheet
---

### Compile iproute2

To cross compile from aarch64 to x86_64, you need to specify some environments before compilation:
``` bash
make CC=x86_64-linux-gnu-gcc LD=x86_64-linux-gnu-ld HOSTCC=gcc LDFLAGS=-static -j`nproc`
```

You may encounter a situation where the compiler complains that it cannot find the definitions of certain symbols, many of which are in libz. To resolve it, you just need to add a signle line in `iproute2-main/Makefile`.

``` diff
  [...]
  LIBNETLINK=../lib/libutil.a ../lib/libnetlink.a
+ LIBNETLINK+=/usr/lib/x86_64-linux-gnu/libz.a
  [...]
```

Another issue is that modules, such as veth, are optionally supported, so they are compiled as .so files. The `ip` then loads these .so files at runtime using `dlopen()`. You can see how it works in `iproute2/ip/iplink.c`.

However, this techique doesn't work if the user compiles `ip` to a static binary, even though these modules are actually compiled into `ip`. You can define a constructor in `iproute2/ip/iplink.c` to manually link these the exported `link_util` objects, allowing `ip` to function correctly.

``` c
// [...]
extern struct link_util veth_link_util;
void init_func(void) __attribute__((constructor));
void init_func(void) {
    struct link_util *l;

    l = &veth_link_util;
    l->next = linkutil_list;
    linkutil_list = l;
}
// [...]
```

Modifying the `iproute2/tc/tc.c` file in the same way to fix the `tc` binary.

``` c
// [...]
extern struct qdisc_util netem_qdisc_util;
void init_func(void) __attribute__((constructor));
void init_func(void) {
    struct qdisc_util *l;

    l = &netem_qdisc_util;
    l->next = qdisc_list;
    qdisc_list = l;
}
// [...]
```

### Compile iputils

``` bash
LDFLAGS=-static meson setup builddir --cross-file ./meson.cross -DUSE_CAP=false
```

The file `meson.cross` is like:
```
[binaries]
c = 'x86_64-linux-gnu-gcc'
pkgconfig = 'x86_64-linux-gnu-pkg-config'

[host_machine]
system = 'linux'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'
```

To rebuild, you need to remove directory `builddir/`.

### Compile libmnl & libnftnl

``` bash
# 1. libmnl
cd ./libmnl-1.0.5
./configure --host=x86_64-linux-gnu --enable-static --prefix=<output_path>
make -j`nproc`

# 2. lbnftnl
cd ./libnftnl-1.2.5
./configure --host=x86_64-linux-gnu --enable-static --prefix=<output_path>
make -j`nproc`

# 3. compile with other file
x86_64-linux-gnu-gcc -o test test.c -L./libnftnl_build/<output_path>/lib      \
                                    -L./libmnl_build/<output_path>/lib        \
                                    -I./libnftnl_build/libnftnl-1.2.5/include \
                                    -I./libmnl_build/libmnl-1.0.5/include -static -lnftnl -lmnl
```

### Ubuntu source list

The file `/etc/apt/sources.list` specifies the repositories from which the system can download software packages.
```
deb http://ports.ubuntu.com/ubuntu-ports lunar main restricted universe multiverse
deb-src http://ports.ubuntu.com/ubuntu-ports lunar main restricted universe multiverse
```

In some cases, you may want to add support for multiple architecture. To do this, you need to perform two steps. First, use the `[arch=]` option to tell Ubuntu which repositories are used for different architectures.
```
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports lunar main restricted universe multiverse
deb-src [arch=arm64] http://ports.ubuntu.com/ubuntu-ports lunar main restricted universe multiverse
```

Next, you must add the desired architecture to package manager. The architecture for host is already included by default.
``` bash
sudo dpkg --add-architecture arm64
sudo apt update
```

Normally, you don't need to update the source file once it's set up. However, some non-LTS releases rearched End of Life very fast quickly, and in such cases, the original repositories URLs may be changed.

In the case I encountered, I updated the URL from `http://ports.ubuntu.com/ubuntu-ports/` to `http://old-releases.ubuntu.com/ubuntu/`, the `apt` command worked normally afterward.
