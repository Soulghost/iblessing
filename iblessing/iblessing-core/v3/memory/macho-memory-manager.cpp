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

uint64_t MachOMemoryManager::allocPath(string path) {
    uint64_t null64 = 0;
    uint64_t pathAddr = alloc(path.length() + 1);
    if (!pathAddr) {
        return 0;
    }
    assert(pathAddr != 0);
    assert(uc_mem_write(uc, pathAddr, path.c_str(), path.length()) == UC_ERR_OK);
    assert(uc_mem_write(uc, pathAddr + path.length(), &null64, 1) == UC_ERR_OK);
    return pathAddr;
}

void MachOMemoryManager::free(uint64_t addr) {
    
}
