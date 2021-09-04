//
//  aarch64-svc-manager.cpp
//  iblessing-core
//
//  Created by Soulghost on 2021/9/4.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-svc-manager.hpp"

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
        assert(false);
        return false;
    }
    
    svcMap[swi].callback(uc, intno, swi, user_data);
    return true;
}

