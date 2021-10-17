//
//  macho-memory-manager.cpp
//  macho-memory-manager
//
//  Created by Soulghost on 2021/10/17.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "macho-memory-manager.hpp"
#include "mach-universal.hpp"

using namespace std;
using namespace iblessing;

MachOMemoryManager::MachOMemoryManager(uc_engine *uc) {
    this->uc = uc;
    allocateBegin = 0x500000000;
    allocateEnd = 0x600000000;
    allocatedCur = allocateBegin;
    
    assert(uc_mem_map(uc, allocateBegin, allocateEnd - allocateBegin, UC_PROT_READ | UC_PROT_WRITE) == UC_ERR_OK);
}

uint64_t MachOMemoryManager::alloc(size_t size, string tag) {
    size = IB_AlignSize(size, 8);
    uint64_t addr = allocatedCur;
    if (allocateEnd - addr < size) {
        assert(false);
        return 0;
    }
    allocatedCur += size;
    return addr;
}

void MachOMemoryManager::free(uint64_t addr) {
    
}
