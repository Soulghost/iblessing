//
//  aarch64-svc-proxy.cpp
//  iblessing-core
//
//  Created by bxl on 2021/11/20.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-svc-proxy.hpp"

using namespace std;
using namespace iblessing;

Aarch64SVCProxy::Aarch64SVCProxy(uc_engine *uc, uint64_t addr, uint64_t size, int swiInitValue) : Aarch64SVCManager(uc, addr, size, swiInitValue) {

}

void normalSyscallX8664(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data){
    printf("normalSyscallX8664");
    int64_t trap_no = 0;
    assert(uc_reg_read(uc, UC_ARM64_REG_X16, &trap_no) == UC_ERR_OK);
    uint64_t args[16] = {0};
    assert(uc_reg_read(uc, UC_ARM64_REG_X0, &args[0]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X1, &args[1]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X2, &args[2]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X3, &args[3]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X4, &args[4]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X5, &args[5]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X6, &args[6]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X7, &args[7]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X8, &args[8]) == UC_ERR_OK);
    
}

void normalSyscallAarch64(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data){
    printf("normalSyscallAarch64");
    
}

void normalSyscall(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data){
#if defined(__LP64__)
    normalSyscallX8664(uc, intno, swi, user_data);
#else
    normalSyscallAarch64(uc, intno, swi, user_data);
#endif
}

bool Aarch64SVCProxy::handleSyscall(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
    normalSyscall(uc, intno, swi, user_data);
    return Aarch64SVCManager::handleSyscall(uc, intno, swi, user_data);
}
