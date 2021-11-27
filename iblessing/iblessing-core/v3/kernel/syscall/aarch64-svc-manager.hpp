//
//  aarch64-svc-manager.hpp
//  iblessing-core
//
//  Created by Soulghost on 2021/9/4.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef aarch64_svc_manager_hpp
#define aarch64_svc_manager_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <map>

#define ensure_uc_mem_read(addr, bytes, size) assert(uc_mem_read(uc, addr, bytes, size) == UC_ERR_OK)
#define ensure_uc_mem_write(addr, bytes, size) assert(uc_mem_write(uc, addr, bytes, size) == UC_ERR_OK)
#define ensure_uc_reg_read(reg, value) assert(uc_reg_read(uc, reg, value) == UC_ERR_OK)
#define ensure_uc_reg_write(reg, value) assert(uc_reg_write(uc, reg, value) == UC_ERR_OK)
#define syscall_return_success syscall_return_value64(0)
#define syscall_return_value(value) do {\
int ret = value;\
assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK); \
} while(0);

#define syscall_return_value64(value) do {\
uint64_t ret = value;\
assert(uc_reg_write(uc, UC_ARM64_REG_X0, &ret) == UC_ERR_OK); \
} while(0);

#ifdef __cplusplus
extern "C" {
#endif
uint64_t svc_uc_mmap(uc_engine *uc, uint64_t start, uint64_t size, int prot, int flags, int fd, int offset);
#ifdef __cplusplus
}
#endif

NS_IB_BEGIN

typedef std::function<void (uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data)> Aarch64SVCCallback;

struct Aarch64SVC {
    int swi;
    Aarch64SVCCallback callback;
};

class Aarch64SVCManager {
public:
    Aarch64SVCManager(uc_engine *uc, uint64_t addr, uint64_t size, int swiInitValue);
    
    uint64_t createSVC(int swi, Aarch64SVCCallback callback);
    uint64_t createSVC(Aarch64SVCCallback callback);
    int allocateSWI();
    uint64_t getAddr();
    uint64_t createSVCWithCustomCode(int swi, uint32_t *code, size_t codelen, Aarch64SVCCallback callback);
    bool handleSVC(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data);
    
protected:
    bool handleSyscall(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data);
    
    // resources
    struct rlimit *rlimit;
    
protected:
    uint64_t addr;
    uint64_t curAddr;
    uint64_t size;
    uc_engine *uc;
    int swiGenerator;
    std::map<int, Aarch64SVC> svcMap;
};

NS_IB_END

#endif /* aarch64_svc_manager_hpp */
