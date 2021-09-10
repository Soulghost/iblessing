//
//  aarch64-svc-manager.cpp
//  iblessing-core
//
//  Created by Soulghost on 2021/9/4.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-svc-manager.hpp"
#include <sys/stat.h>

using namespace std;
using namespace iblessing;

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
                
                if (fd >= 0 && fd < 3) {
                    
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
                    struct posix_stat {
                        dev_t     st_dev;     /* ID of device containing file 32 */
                        ino_t     st_ino;     /* inode number 64 */
                        mode_t    st_mode;    /* protection 16 */
                        nlink_t   st_nlink;   /* number of hard links 16 */
                        uid_t     st_uid;     /* user ID of owner 32 */
                        gid_t     st_gid;     /* group ID of owner 32 */
                        dev_t     st_rdev;    /* device ID (if special file) 32 */
                        off_t     st_size;    /* total size, in bytes */
                        blksize_t st_blksize; /* blocksize for file system I/O */
                        blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
                        time_t    _st_atime;   /* time of last access */
                        time_t    _st_mtime;   /* time of last modification */
                        time_t    _st_ctime;   /* time of last status change */
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
    }
    return false;
}
