//
//  aarch64-svc-manager.cpp
//  iblessing-core
//
//  Created by Soulghost on 2021/9/4.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-svc-manager.hpp"
#include <sys/stat.h>
#include "mach-universal.hpp"

using namespace std;
using namespace iblessing;

#define TASK_BOOTSTRAP_PORT 4
#define BOOTSTRAP_PORT 11

Aarch64SVCManager::Aarch64SVCManager(uc_engine *uc, uint64_t addr, uint64_t size, int swiInitValue) {
    this->uc = uc;
    this->addr = addr;
    this->curAddr = addr;
    this->size = size;
    this->swiGenerator = swiInitValue;
    
    uc_err err = uc_mem_map(uc, addr, size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("[-] AArch64SVCManager - svc allocate error %s\n", uc_strerror(err));
        assert(false);
    }
    
    this->rlimit = nullptr;
}

uint64_t Aarch64SVCManager::createSVC(Aarch64SVCCallback callback) {
    uint64_t addr = createSVC(swiGenerator, callback);
    if (addr > 0) {
        swiGenerator += 1;
    }
    return addr;
}

uint64_t Aarch64SVCManager::createSVC(int swi, Aarch64SVCCallback callback) {
    if (addr + size - curAddr < 8) {
        return 0;
    }
    if (svcMap.find(swi) != svcMap.end()) {
        return 0;
    }
    
    uint32_t svcCommand = 0xd4000001 | (swi << 5);
    uint32_t retCommand = 0xd65f03c0;
    uint64_t startAddr = curAddr;
    assert(uc_mem_write(uc, curAddr, &svcCommand, 4) == UC_ERR_OK);
    assert(uc_mem_write(uc, curAddr + 4, &retCommand, 4) == UC_ERR_OK);
    curAddr += 8;
    
    Aarch64SVC svc;
    svc.swi = swi;
    svc.callback = callback;
    svcMap[swi] = svc;
    return startAddr;
}

bool Aarch64SVCManager::handleSVC(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
    assert(uc == this->uc);
    if (svcMap.find(swi) == svcMap.end()) {
        if (swi == 0x80) {
            return handleSyscall(uc, intno, swi, user_data);
        }
        assert(false);
        return false;
    }
    
    svcMap[swi].callback(uc, intno, swi, user_data);
    return true;
}

// FIXME: call to mod_init_func
// 0x100d96e94 -> 0x100d84924 -> 0x100d74310 -> getrlimit -> 0x100d32d08 -> 0x100d84928
// -> 0x100d84988 -> 0x100d75c84 -> 0x100d75d38 -> 0x100d75d6c(fstat lr)
// -> 0x100d75c88 -> 0x100d75c98(isatty) -> 0x100d3debc(call to ioctl)
// -> 0x100d3dec0(ioctl lr) -> 0x100d75cc8(malloc)
// -> 0x100e9e308(libsystem_malloc)
bool Aarch64SVCManager::handleSyscall(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
    int64_t trap_no = 0;
    assert(uc_reg_read(uc, UC_ARM64_REG_X16, &trap_no) == UC_ERR_OK);
    if (trap_no > 0) {
        // posix
        switch (trap_no) {
            // ioctl
            case 54: {
                int fd;
                int ret = 0;
                uint64_t request;
                assert(uc_reg_read(uc, UC_ARM64_REG_W0, &fd) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_X1, &request) == UC_ERR_OK);
                
                if (fd == 1) {
                    uint64_t argpAddr = 0;
                    assert(uc_reg_read(uc, UC_ARM64_REG_X2, &argpAddr) == UC_ERR_OK);
                    
                    int arg0Val = 3;
                    assert(uc_mem_write(uc, argpAddr, &arg0Val, 4) == UC_ERR_OK);
                } else {
                    ret = 1;
                    assert(false);
                }
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            // getrlimit
            case 194: {
                int resource = 0;
                int ret = 0;
                uint64_t rlp = 0;
                assert(uc_reg_read(uc, UC_ARM64_REG_W0, &resource) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_X1, &rlp) == UC_ERR_OK);
                int type = resource & (_RLIMIT_POSIX_FLAG - 1);
                printf("[+] handle syscall getrlimit(194) with resource %d, type 0x%x, rlp 0x%llx\n", resource, type, rlp);
                if (type == RLIMIT_NOFILE) {
                    if (!this->rlimit) {
                        this->rlimit = (struct rlimit *)malloc(sizeof(struct rlimit));
                        this->rlimit->rlim_cur = 128;
                        this->rlimit->rlim_max = 256;
                    }
                    
                    assert(uc_mem_write(uc, rlp, &this->rlimit, sizeof(struct rlimit)) == UC_ERR_OK);
//                    assert(uc_mem_write(uc, rlp + __offsetof(struct rlimit, rlim_cur), &this->rlimit->rlim_cur, 8) == UC_ERR_OK);
//                    assert(uc_mem_write(uc, rlp + __offsetof(struct rlimit, rlim_max), &this->rlimit->rlim_max, 8) == UC_ERR_OK);
                } else {
                    assert(false);
                    ret = 1;
                }
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
                
            // fstat64
            case 339: {
                int fd = 0;
                int ret = 0;
                uint64_t buf = 0;
                assert(uc_reg_read(uc, UC_ARM64_REG_W0, &fd) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_X1, &buf) == UC_ERR_OK);
                printf("[+] handle syscall fstat64(339) with fd %d, buf 0x%llx\n", fd, buf);
                if (fd >= 0 && fd < 3) {
                    int st_mode;
                    if (fd == 1) {
                        st_mode = S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO;
                    } else {
                        st_mode = S_IFREG;
                    }
                    
                    int blockSize = 0x4000;
                    struct posix_timesec {
                        long tv_sec;
                        long tv_nsec;
                    };
                    struct posix_stat {
                        dev_t     st_dev;     /* ID of device containing file 32 */
                        mode_t    st_mode;    /* protection 16 */
                        nlink_t   st_nlink;   /* number of hard links 16 */
                        ino_t     st_ino;     /* inode number 64 */
                        uid_t     st_uid;     /* user ID of owner 32 */
                        gid_t     st_gid;     /* group ID of owner 32 */
                        dev_t     st_rdev;    /* device ID (if special file) 32 */
                        struct posix_timesec st_atimespec;  /* time of last access */
                        struct posix_timesec st_mtimespec;  /* time of last data modification */
                        struct posix_timesec st_ctimespec;  /* time of last status change */
                        struct posix_timesec st_birthtimespec; /* time of file creation(birth) */
                        off_t     st_size;    /* total size, in bytes */
                        blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
                        blksize_t st_blksize; /* blocksize for file system I/O */
                        uint32_t    st_flags; /* user defined flags for file */
                        uint32_t    st_gen;   /* file generation number */
                    };
                    struct posix_stat s = { 0 };
                    s.st_dev = 1;
                    s.st_mode = st_mode;
                    s.st_size = blockSize * 100;
                    s.st_blocks = (s.st_size + blockSize - 1) / blockSize;
                    s.st_blksize = blockSize;
                    s.st_ino = 7;
                    s.st_uid = 0;
                    s.st_gid = 0;
                    assert(uc_mem_write(uc, buf, &s, sizeof(struct posix_stat)) == UC_ERR_OK);
                } else {
                    assert(false);
                    ret = 1;
                }
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            default:
                break;
        }
    } else if (trap_no < 0) {
        // mach
        int64_t call_number = -trap_no;
        switch (call_number) {
            case 26: { // mach_reply_port
                int ret = 4;
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            case 28: { // task_self_trap
                int ret = 1;
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            case 31: { // mach_msg_trap
//                PAD_ARG_(user_addr_t, msg);
//                PAD_ARG_(mach_msg_option_t, option);
//                PAD_ARG_(mach_msg_size_t, send_size);
//                PAD_ARG_(mach_msg_size_t, rcv_size);
//                PAD_ARG_(mach_port_name_t, rcv_name);
//                PAD_ARG_(mach_msg_timeout_t, timeout);
//                PAD_ARG_(mach_msg_priority_t, priority);
//                PAD_ARG_8
//                    PAD_ARG_(user_addr_t, rcv_msg); /* Unused on mach_msg_trap */
                uint64_t msg;
                int option;
                uint32_t send_size, rcv_size, rcv_name, timeout, priority;
                assert(uc_reg_read(uc, UC_ARM64_REG_X0, &msg) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W1, &option) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W2, &send_size) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W3, &rcv_size) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W4, &rcv_name) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W5, &timeout) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W6, &priority) == UC_ERR_OK);
                
                uint32_t msgSize = std::max(send_size, rcv_size);
                ib_mach_msg_header_t *hdr = (ib_mach_msg_header_t *)malloc(msgSize);
                assert(hdr != NULL);
                assert(uc_mem_read(uc, msg, hdr, msgSize) == UC_ERR_OK);
                switch (hdr->msgh_id) {
                    case 3409: { // task_get_special_port
                        #pragma pack(push, 4)
                        typedef struct {
                            ib_mach_msg_header_t Head;
                            ib_NDR_record_t NDR;
                            int which_port;
                        } Request __attribute__((unused));
                        #pragma pack(pop)
                        Request *request = (Request *)hdr;
                        assert(request->which_port == TASK_BOOTSTRAP_PORT);
                        
                        #pragma pack(push, 4)
                        typedef struct {
                            ib_mach_msg_header_t Head;
                            /* start of the kernel processed data */
                            ib_mach_msg_body_t msgh_body;
                            ib_mach_msg_port_descriptor_t special_port;
                            /* end of the kernel processed data */
                        } Reply __attribute__((unused));
                        #pragma pack(pop)
                        Reply *OutP = (Reply *)hdr;
                        #define IB_MACH_MSGH_BITS_COMPLEX          0x80000000U     /* message is complex */
                        #define IB_MACH_MSG_PORT_DESCRIPTOR  0

                        OutP->Head.msgh_remote_port = hdr->msgh_local_port;
                        OutP->Head.msgh_local_port = 0;
                        OutP->Head.msgh_id += 100;
                        OutP->Head.msgh_bits = (hdr->msgh_bits & 0xff) | IB_MACH_MSGH_BITS_COMPLEX;
                        OutP->Head.msgh_size = (ib_mach_msg_size_t)(sizeof(Reply));
                        
                        OutP->msgh_body.msgh_descriptor_count = 1;
                        OutP->special_port.name = BOOTSTRAP_PORT;
                        OutP->special_port.pad1 = 0;
                        OutP->special_port.pad2 = 0;
                        OutP->special_port.disposition = 19; // FIXME: unidbg set to 17
                        OutP->special_port.type = IB_MACH_MSG_PORT_DESCRIPTOR;
                        assert(uc_mem_write(uc, msg, OutP, OutP->Head.msgh_size) == UC_ERR_OK);
                        
                        int ret = 0;
                        assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                        return true;
                        break;
                    }
                    default:
                        assert(false);
                        break;
                }
                
                free(hdr);
            }
            default:
                assert(false);
                break;
        }
    }
    assert(false);
    return false;
}
