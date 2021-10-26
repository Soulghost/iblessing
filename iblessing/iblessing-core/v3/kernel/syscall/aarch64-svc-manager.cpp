//
//  aarch64-svc-manager.cpp
//  iblessing-core
//
//  Created by Soulghost on 2021/9/4.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-svc-manager.hpp"
#include <sys/stat.h>
#include "ib_pthread.hpp"
#include "mach-universal.hpp"
#include "aarch64-machine.hpp"
#include "macho-memory.hpp"
#include "uc_debugger_utils.hpp"

using namespace std;
using namespace iblessing;

#define TASK_BOOTSTRAP_PORT 4
#define BOOTSTRAP_PORT 11
#define CLOCK_SERVER_PORT 13
#define SEMAPHORE_PORT 14

#define IB_FD_URANDOM 3

uint64_t svc_uc_mmap(uc_engine *uc, uint64_t start, uint64_t mask, uint64_t size, int prot, int flags, int fd, int offset) {
    uint64_t aligned_size = ((size - 1) / 16384 + 1) * 16384;
    assert(!(flags & IB_MAP_FIXED));
    assert(!(flags & IB_MAP_FILE));
    // FIXME: tricky kern_mmap
    static uint64_t mmapHeapPtr = 0x400000000;
    if (mask > 0) {
        mmapHeapPtr = IB_AlignSize(mmapHeapPtr, mask + 1);
    }
    
    print_uc_mem_regions(uc);
    uc_err err = uc_mem_map(uc, mmapHeapPtr, aligned_size, prot);
    if (err) {
        printf("[-] cannot mmap at 0x%llx, error %s\n", mmapHeapPtr, uc_strerror(err));
        assert(false);
    }
    
//    // do clean
//    void *nullChunk = calloc(1, aligned_size);
//    uc_mem_write(uc, mmapHeapPtr, nullChunk, aligned_size);
//    free(nullChunk);
    
    print_uc_mem_regions(uc);
    uint64_t addr = mmapHeapPtr;
    mmapHeapPtr += aligned_size;
    return addr;
}

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

int Aarch64SVCManager::allocateSWI() {
    return swiGenerator++;
}

uint64_t Aarch64SVCManager::getAddr() {
    return curAddr;
}

uint64_t Aarch64SVCManager::createSVCWithCustomCode(int swi, uint32_t *code, size_t codelen, Aarch64SVCCallback callback) {
    if (addr + size - curAddr < codelen) {
        return 0;
    }
    if (svcMap.find(swi) != svcMap.end()) {
        return 0;
    }
    
    uint64_t startAddr = curAddr;
    assert(uc_mem_write(uc, curAddr, code, codelen) == UC_ERR_OK);
    curAddr += codelen;
    
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
            case 20: {
                syscall_return_value(2333);
                return true;
            }
            case 24:   // getuid
            case 25:   // geteuid
            case 43:   // getegid
            case 47: { // getgid
                syscall_return_value(0);
                return true;
            }
            // ioctl
            case 54: {
                int fd;
                int ret = 0;
                uint64_t request;
                assert(uc_reg_read(uc, UC_ARM64_REG_W0, &fd) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W1, &request) == UC_ERR_OK);
                
                if (fd == 1) {
                    uint64_t argpAddr = 0;
                    assert(uc_reg_read(uc, UC_ARM64_REG_X2, &argpAddr) == UC_ERR_OK);
                    
                    int arg0Val = 3;
                    assert(uc_mem_write(uc, argpAddr, &arg0Val, sizeof(int)) == UC_ERR_OK);
                } else {
                    ret = 1;
                    assert(false);
                }
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            case 74: { // mprotect
                uint64_t addr, length;
                int prot;
                ensure_uc_reg_read(UC_ARM64_REG_X0, &addr);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &length);
                ensure_uc_reg_read(UC_ARM64_REG_W2, &prot);
                uint64_t alignedAddr = addr / 0x1000 * 0x1000;
                uint64_t offset = addr - alignedAddr;
                uint64_t alignedLength = IB_AlignSize(length + offset, 0x4000);
                uc_err err = uc_mem_protect(uc, alignedAddr, alignedLength, prot);
                assert(err == UC_ERR_OK);
                syscall_return_success;
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
            
            // sysctl
            case 202: {
#if 0
                int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
                int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
                int sysctlnametomib(const char *name, int *mibp, size_t *sizep);
#endif
                uint64_t nameAddr = 0;
                int nameLen = 0;
                assert(uc_reg_read(uc, UC_ARM64_REG_X0, &nameAddr) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W1, &nameLen) == UC_ERR_OK);
                int name = 0;
                assert(uc_mem_read(uc, nameAddr, &name, sizeof(int)) == UC_ERR_OK);
                uint64_t bufferAddr = 0, bufferSizeAddr = 0;
                assert(uc_reg_read(uc, UC_ARM64_REG_X2, &bufferAddr) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_X3, &bufferSizeAddr) == UC_ERR_OK);
                switch (name) {
                    case 0: // CTL_UNSPEC
                        assert(false);
                        break;
                    case 1: {// KERN
                        uint32_t action = 0;
                        assert(uc_mem_read(uc, nameAddr + 4, &action, sizeof(int)) == UC_ERR_OK);
                        switch (action) {
                            case 59: { // KERN_USRSTACK64
                                if (bufferSizeAddr != 0) {
                                    uint64_t bufferSize = 8;
                                    assert(uc_mem_write(uc, bufferSizeAddr, &bufferSize, sizeof(uint64_t)) == UC_ERR_OK);
                                }
                                if (bufferAddr != 0) {
                                    uint64_t stackBase = UnicornStackTopAddr;
                                    assert(uc_mem_write(uc, bufferAddr, &stackBase, sizeof(uint64_t)) == UC_ERR_OK);
                                }
                                int ret = 0;
                                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                                return true;
                            }
                        }
                        break;
                    }
                    default:
                        assert(false);
                        break;
                }
                return true;
            }
            case 286: { // pthread_getugid_np
                uint64_t uidAddr, gidAddr;
                ensure_uc_reg_read(UC_ARM64_REG_X0, &uidAddr);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &gidAddr);
                uint64_t zero = 0;
                ensure_uc_mem_write(uidAddr, &zero, sizeof(uint64_t));
                ensure_uc_mem_write(gidAddr, &zero, sizeof(uint64_t));
                syscall_return_success;
                return true;
            }
            case 327: { // issetugid
                printf("[Stalker][+] handle issetugid -> 0\n");
                syscall_return_success;
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
            case 366: { // bsdthread_register
                uint64_t thread_start, start_wqthread;
                int page_size;
                uint64_t data, offset;
                int data_size;
            
                ensure_uc_reg_read(UC_ARM64_REG_X0, &thread_start);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &start_wqthread);
                ensure_uc_reg_read(UC_ARM64_REG_W2, &page_size);
                ensure_uc_reg_read(UC_ARM64_REG_X3, &data);
                ensure_uc_reg_read(UC_ARM64_REG_W4, &data_size);
                ensure_uc_reg_read(UC_ARM64_REG_X5, &offset);
                
                printf("[Stalker][+] handle bsdthread_register: thread_start: 0x%llx, start_wqthread 0x%llx, page_size 0x%x, data 0x%llx, data_size 0x%x, offset 0x%llx\n", thread_start, start_wqthread, page_size, data, data_size, offset);
                
                int ret = 0;
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            case 372: { // thread_selfid
                int ret = 1;
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            case 381: { // sandbox_ms
                uint64_t policyAddr, args;
                int call;
                ensure_uc_reg_read(UC_ARM64_REG_X0, &policyAddr);
                ensure_uc_reg_read(UC_ARM64_REG_W1, &call);
                ensure_uc_reg_read(UC_ARM64_REG_X2, &args);
                char *policy = MachoMemoryUtils::uc_read_string(uc, policyAddr, 100);
                assert(policy != NULL);
                printf("[Stalker][+][Sandbox] apply sandbox check by sandbox_ms with policy %s, call %d, args 0x%llx\n", policy, call, args);
                free(policy);
                syscall_return_success;
                return true;
            }
            case 396: { // read_NOCANCEL
                int fd, count;
                uint64_t bufferAddr;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &fd);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &bufferAddr);
                ensure_uc_reg_read(UC_ARM64_REG_W2, &count);
                if (fd == IB_FD_URANDOM) {
                    int chunkCnt = count / sizeof(int);
                    int rest = count % sizeof(int);
                    for (int i = 0; i < chunkCnt; i++) {
                        int val = i % 255;
                        ensure_uc_mem_write(bufferAddr, &val, sizeof(int));
                        bufferAddr += sizeof(int);
                    }
                    
                    if (rest > 0) {
                        int tailVal = 255;
                        ensure_uc_mem_write(bufferAddr, &tailVal, rest);
                    }
                } else {
                    assert(false);
                }
                
                uint64_t readLen = count;
                ensure_uc_reg_write(UC_ARM64_REG_X0, &readLen);
                return true;
            }
            case 397: { // write_NOCANCEL
                int fd, count;
                uint64_t bufferAddr;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &fd);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &bufferAddr);
                ensure_uc_reg_read(UC_ARM64_REG_W2, &count);
                assert(fd == 1);
                char *content = MachoMemoryUtils::uc_read_string(uc, bufferAddr, count);
                printf("[Stalker][STDOUT] %s", content);
                free(content);
                syscall_return_success;
                return true;
            }
            case 398: { // open_NOCANCEL
                uint64_t pathAddr;
                int oflags, mode;
                ensure_uc_reg_read(UC_ARM64_REG_X0, &pathAddr);
                ensure_uc_reg_read(UC_ARM64_REG_W1, &oflags);
                ensure_uc_reg_read(UC_ARM64_REG_W2, &mode);
                char *path = MachoMemoryUtils::uc_read_string(uc, pathAddr, 1000);
                int fd = -1;
                if (strcmp(path, "/dev/urandom") == 0 ||
                    strcmp(path, "/dev/random") == 0 ||
                    strcmp(path, "/dev/srandom") == 0) {
                    fd = IB_FD_URANDOM;
                } else {
                    assert(false);
                }
                free(path);
                ensure_uc_reg_write(UC_ARM64_REG_W0, &fd);
                
                uint64_t cspr = 0;
                assert(uc_reg_read(uc, UC_ARM64_REG_NZCV, &cspr) == UC_ERR_OK);
                // clear carry
                cspr &= ~(1UL << 29);
                ensure_uc_reg_write(UC_ARM64_REG_NZCV, &cspr);
                return true;
            }
            case 399: { // close_NOCANCEL
                int fd;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &fd);
                assert(fd == IB_FD_URANDOM);
                printf("[Stalker][+] handle close_NOCANCEL with fd %d\n", fd);
                return true;
            }
            case 0x80000000: { // pthread_set_self
                uint64_t x3 = 0;
                assert(uc_reg_read(uc, UC_ARM64_REG_X3, &x3) == UC_ERR_OK);
                switch (x3) {
                    case 2: { // pthread_set_self
                        uint64_t selfAddr = 0;
                        assert(uc_reg_read(uc, UC_ARM64_REG_X0, &selfAddr) == UC_ERR_OK);
                        uint64_t threadAddr = 0;
                        assert(uc_mem_read(uc, selfAddr, &threadAddr, sizeof(uint64_t)) == UC_ERR_OK);
                        ib_pthread *pthread = (ib_pthread *)malloc(sizeof(ib_pthread));
                        assert(uc_mem_read(uc, threadAddr, pthread, sizeof(ib_pthread)) == UC_ERR_OK);
                        
                        uint64_t tsdAddr = threadAddr + __offsetof(ib_pthread, self);
                        assert(uc_reg_write(uc, UC_ARM64_REG_TPIDRRO_EL0, &tsdAddr) == UC_ERR_OK);
                        
                        // FIXME: set errno
                        int ret = 0;
                        assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                        return true;
                    }
                    default:
                        assert(false);
                        break;
                }
            }
            default:
                break;
        }
    } else if (trap_no < 0) {
        // mach
        int64_t call_number = -trap_no;
        switch (call_number) {
            case 10: { // _kernelrpc_mach_vm_allocate_trap
                int target, flags;
                uint64_t size, addrPtr;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &target);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &addrPtr);
                ensure_uc_reg_read(UC_ARM64_REG_X2, &size);
                ensure_uc_reg_read(UC_ARM64_REG_W3, &flags);
//                int tag = flags >> 24;
                assert(flags & IB_VM_FLAGS_ANYWHERE);
                uint64_t addr = svc_uc_mmap(uc, 0, 0, IB_AlignSize(size, 0x4000), UC_PROT_READ | UC_PROT_WRITE, 0, -1, 0);
                void *zeros = calloc(1, size);
                uc_mem_write(uc, addr, zeros, size);
                free(zeros);
                ensure_uc_mem_write(addrPtr, &addr, sizeof(uint64_t));
                syscall_return_success;
                return true;
            }
            case 12: { // _kernelrpc_mach_vm_deallocate_trap
                // FIXME: mumap
                ib_mach_port_t target;
                uint64_t addr, size;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &target);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &addr);
                ensure_uc_reg_read(UC_ARM64_REG_X2, &size);
                printf("[Stalker][+][Mach] mach_vm_deallocate for task %d at 0x%llx, size 0x%llx\n", target, addr, size);
                syscall_return_success;
                return true;
            }
            case 15: { // _kernelrpc_mach_vm_map_trap
#if 0
                extern kern_return_t _kernelrpc_mach_vm_map_trap(
                    mach_port_name_t target,
                    mach_vm_offset_t *address,
                    mach_vm_size_t size,
                    mach_vm_offset_t mask,
                    int flags,
                    vm_prot_t cur_protection
                );
#endif
                ib_mach_port_t target;
                uint64_t addrPtr, size, mask;
                int flags, cur_port;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &target);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &addrPtr);
                ensure_uc_reg_read(UC_ARM64_REG_X2, &size);
                ensure_uc_reg_read(UC_ARM64_REG_X3, &mask);
                ensure_uc_reg_read(UC_ARM64_REG_W4, &flags);
                ensure_uc_reg_read(UC_ARM64_REG_W5, &cur_port);
                uint64_t addr;
                ensure_uc_mem_read(addrPtr, &addr, sizeof(uint64_t));
                // FIXME: mem mask
                uint64_t allocatedAddr = 0;
                allocatedAddr = svc_uc_mmap(uc, 0, mask, size, cur_port, flags, -1, 0);
                
                assert(allocatedAddr != 0);
                // FIXME: tricky kern_mmap
                
                ensure_uc_mem_write(addrPtr, &allocatedAddr, sizeof(uint64_t));
                syscall_return_success;
                return true;
            }
            case 18: { // _kernelrpc_mach_port_deallocate_trap
                int task, name;
                assert(uc_reg_read(uc, UC_ARM64_REG_W0, &task) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W1, &name) == UC_ERR_OK);
                printf("[+] _kernelrpc_mach_port_deallocate_trap for port %d in task %d\n", name, task);
                int ret = 0;
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            case 26: { // mach_reply_port
                int ret = 4;
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            case 27: {
                int ret = 3;
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            case 28: { // task_self_trap
                int ret = 1;
                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                return true;
            }
            case 29: { // host_self_trap
                int ret = 2;
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
                    case 200: { // host_info
                        #pragma pack(push, 4)
                        typedef struct {
                            ib_mach_msg_header_t Head;
                            ib_NDR_record_t NDR;
                            ib_host_flavor_t flavor;
                            ib_mach_msg_type_number_t host_info_outCnt;
                            ib_mach_msg_trailer_t trailer;
                        } Request __attribute__((unused));
                        #pragma pack(pop)
                        
                        #pragma pack(push, 4)
                        typedef struct {
                            ib_mach_msg_header_t Head;
                            ib_NDR_record_t NDR;
                            ib_kern_return_t RetCode;
                            ib_mach_msg_type_number_t host_info_outCnt;
                            int host_info_out[68];
                        } Reply __attribute__((unused));
                        #pragma pack(pop)
                        
                        Request *request = (Request *)hdr;
                        switch (request->flavor) {
                            case 5: { // HOST_PRIORITY_INFO
                                struct host_priority_info {
                                    integer_t       kernel_priority;
                                    integer_t       system_priority;
                                    integer_t       server_priority;
                                    integer_t       user_priority;
                                    integer_t       depress_priority;
                                    integer_t       idle_priority;
                                    integer_t       minimum_priority;
                                    integer_t       maximum_priority;
                                };
                                
                                #pragma pack(push, 4)
                                typedef struct {
                                    ib_mach_msg_header_t Head;
                                    ib_NDR_record_t NDR;
                                    ib_kern_return_t RetCode;
                                    ib_mach_msg_type_number_t host_info_outCnt;
                                    struct host_priority_info info;
                                } HostPriorityReply __attribute__((unused));
                                #pragma pack(pop)
                                HostPriorityReply *reply = (HostPriorityReply *)hdr;
                                reply->Head.msgh_remote_port = hdr->msgh_local_port;
                                reply->Head.msgh_local_port = 0;
                                reply->Head.msgh_id += 100;
                                reply->Head.msgh_bits &= 0xff;
                                reply->Head.msgh_size = sizeof(HostPriorityReply);
                                reply->info.kernel_priority    = 0;
                                reply->info.system_priority    = 0;
                                reply->info.server_priority    = 0;
                                reply->info.user_priority    = 0;
                                reply->info.depress_priority    = 0;
                                reply->info.idle_priority    = 0;
                                reply->info.minimum_priority    = -10;
                                reply->info.maximum_priority    = 10;
                                reply->RetCode = 0;
                                reply->host_info_outCnt = 8;
                                assert(uc_mem_write(uc, msg, reply, reply->Head.msgh_size) == UC_ERR_OK);
                                int ret = 0;
                                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                                return true;
                                break;
                            }
                            default:
                                break;
                        }
                        break;
                    }
                    case 206: { // host_get_clock_service
                        #pragma pack(push, 4)
                        typedef struct {
                            ib_mach_msg_header_t Head;
                            ib_NDR_record_t NDR;
                            int clock_id;
                            ib_mach_msg_trailer_t trailer;
                        } Request __attribute__((unused));
                        #pragma pack(pop)
                        
                        Request *request = (Request *)hdr;
                        printf("[+][Stalker][Syscall][Mach] receive client host_get_clock_service mach_msg with clock_id %d\n", request->clock_id);
                        
                        #pragma pack(push, 4)
                        typedef struct {
                            ib_mach_msg_header_t Head;
                            /* start of the kernel processed data */
                            ib_mach_msg_body_t msgh_body;
                            ib_mach_msg_port_descriptor_t clock_server;
                            /* end of the kernel processed data */
                        } Reply __attribute__((unused));
                        #pragma pack(pop)
                        
                        Reply *OutP = (Reply *)hdr;
                        OutP->Head.msgh_remote_port = hdr->msgh_local_port;
                        OutP->Head.msgh_local_port = 0;
                        OutP->Head.msgh_id += 100;
                        OutP->Head.msgh_bits = (hdr->msgh_bits & 0xff) | IB_MACH_MSGH_BITS_COMPLEX;
                        OutP->Head.msgh_size = (ib_mach_msg_size_t)(sizeof(Reply));
                        
                        OutP->msgh_body.msgh_descriptor_count = 1;
                        OutP->clock_server.name = CLOCK_SERVER_PORT;
                        OutP->clock_server.pad1 = 0;
                        OutP->clock_server.pad2 = 0;
                        OutP->clock_server.disposition = 17;
                        OutP->clock_server.type = IB_MACH_MSG_PORT_DESCRIPTOR;
                        assert(uc_mem_write(uc, msg, OutP, OutP->Head.msgh_size) == UC_ERR_OK);
                        
                        syscall_return_success;
                        return true;
                    }
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
                        OutP->Head.msgh_remote_port = hdr->msgh_local_port;
                        OutP->Head.msgh_local_port = 0;
                        OutP->Head.msgh_id += 100;
                        OutP->Head.msgh_bits = (hdr->msgh_bits & 0xff) | IB_MACH_MSGH_BITS_COMPLEX;
                        OutP->Head.msgh_size = (ib_mach_msg_size_t)(sizeof(Reply));
                        
                        OutP->msgh_body.msgh_descriptor_count = 1;
                        OutP->special_port.name = BOOTSTRAP_PORT;
                        OutP->special_port.pad1 = 0;
                        OutP->special_port.pad2 = 0;
                        // check libsystem_kernel.dylib task_get_special_port
                        OutP->special_port.disposition = 17;
                        OutP->special_port.type = IB_MACH_MSG_PORT_DESCRIPTOR;
                        assert(uc_mem_write(uc, msg, OutP, OutP->Head.msgh_size) == UC_ERR_OK);
                        
                        int ret = 0;
                        assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                        return true;
                    }
                    case 3418: { // semaphore_create
                        #pragma pack(push, 4)
                        typedef struct {
                            ib_mach_msg_header_t Head;
                            ib_NDR_record_t NDR;
                            int policy;
                            int value;
                            ib_mach_msg_trailer_t trailer;
                        } Request __attribute__((unused));
                        #pragma pack(pop)
                        
                        Request *request = (Request *)hdr;
                        printf("[+][Stalker][Syscall][Mach] receive client semaphore_create mach_msg with policy %d, value %d\n", request->policy, request->value);
                        
                        #pragma pack(push, 4)
                        typedef struct {
                            ib_mach_msg_header_t Head;
                            /* start of the kernel processed data */
                            ib_mach_msg_body_t msgh_body;
                            ib_mach_msg_port_descriptor_t semaphore;
                            /* end of the kernel processed data */
                        } Reply __attribute__((unused));
                        #pragma pack(pop)
                        
                        Reply *OutP = (Reply *)hdr;
                        OutP->Head.msgh_remote_port = hdr->msgh_local_port;
                        OutP->Head.msgh_local_port = 0;
                        OutP->Head.msgh_id += 100;
                        OutP->Head.msgh_bits = (hdr->msgh_bits & 0xff) | IB_MACH_MSGH_BITS_COMPLEX;
                        OutP->Head.msgh_size = (ib_mach_msg_size_t)(sizeof(Reply));
                        
                        OutP->msgh_body.msgh_descriptor_count = 1;
                        OutP->semaphore.name = SEMAPHORE_PORT;
                        OutP->semaphore.pad1 = 0;
                        OutP->semaphore.pad2 = 0;
                        OutP->semaphore.disposition = 17;
                        OutP->semaphore.type = IB_MACH_MSG_PORT_DESCRIPTOR;
                        assert(uc_mem_write(uc, msg, OutP, OutP->Head.msgh_size) == UC_ERR_OK);
                        
                        int ret = 0;
                        assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                        return true;
                    }
                    default:
                        assert(false);
                        break;
                }
                
                free(hdr);
            }
            case 36: { // semaphore_wait_trap
                ib_mach_port_t semaphore_port = 0;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &semaphore_port);
                assert(semaphore_port == SEMAPHORE_PORT);
                printf("[+][Stalker][Syscall][Mach] semaphore_wait_trap for port %d\n", semaphore_port);
                syscall_return_success;
                return true;
            }
            default:
                assert(false);
                break;
        }
    }
    assert(false);
    return false;
}
