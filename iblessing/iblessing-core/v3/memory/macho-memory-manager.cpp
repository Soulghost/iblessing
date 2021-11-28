//
//  macho-memory-manager.cpp
//  macho-memory-manager
//
//  Created by Soulghost on 2021/10/17.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "macho-memory-manager.hpp"
#include "mach-universal.hpp"
extern "C" {
#include <sys/types.h>
#include <sys/mman.h>
}

using namespace std;
using namespace iblessing;


MachOMemoryManager::MachOMemoryManager(uc_engine *uc) {
    this->uc = uc;
    allocateBegin = 0x500000000;
    allocateEnd = 0x600000000;
    allocatedCur = allocateBegin;
    
    stackBegin = IB_STACK_START;
    stackEnd = IB_STACK_END;
    
    use_shared = true;
    
    if(use_shared){
        mmapSharedMem(stackBegin, stackEnd-stackBegin, PROT_READ|PROT_WRITE);
        mmapSharedMem(allocateBegin, allocateEnd-allocateBegin, PROT_READ|PROT_WRITE);
        
    }else{
        assert(uc_mem_map(uc, allocateBegin, allocateEnd - allocateBegin, UC_PROT_READ | UC_PROT_WRITE) == UC_ERR_OK);
    }
}

#define ROUNDUP(a, b) (((a) + ((b) - 1)) & (~((b) - 1)))

uint64_t MachOMemoryManager::alloc(size_t size, string tag) {
    size = IB_AlignSize(size, 8);
    uint64_t addr = allocatedCur;
    if(!use_shared || addr < 0x1000){
        if (allocateEnd - addr < size) {
            assert(false);
            return 0;
        }
        allocatedCur += size;
        
    }else{
        size_t size_rounded = ROUNDUP(size, 0x1000);
        addr = (uint64_t)valloc(size_rounded);
        assert(uc_mem_map_ptr(uc, addr, size_rounded, UC_PROT_READ | UC_PROT_WRITE, (void *)addr) == UC_ERR_OK);
    }
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

void MachOMemoryManager::dealloc(uint64_t addr) {
    if(use_shared && (addr < allocateBegin || addr >= allocateEnd)){
        free((void *)addr);
    }
}

void *MachOMemoryManager::mmapSharedMem(uint64_t guest_addr, size_t size, int prot) {
    size_t size_rounded = ROUNDUP(size, 0x1000);
    void *mmaped_addr = mmap((void *)guest_addr, size_rounded, prot, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    perror("mmap");
    assert(mmaped_addr == (void *)guest_addr);
    assert(uc_mem_map_ptr(uc, guest_addr, size_rounded, UC_PROT_READ | UC_PROT_WRITE, mmaped_addr) == UC_ERR_OK);
    return mmaped_addr;
}

uint64_t MachOMemoryManager::stackNew() {
    uint64_t newStackAddr = stackBegin;
    bool found = false;
    while(newStackAddr < stackEnd){
        if(usedStackStarts.find(newStackAddr) == usedStackStarts.end()){
            found = true;
            usedStackStarts.insert(newStackAddr);
            break;
        }
        newStackAddr += IB_STACK_SIZE;
    }
    if(found){
        return newStackAddr;
    }else{
        return NULL;
    }
}

void MachOMemoryManager::stackDelete(uint64_t addrInStack){
    uint64_t stackStart = addrInStack & IB_STACK_MASK;
    if(usedStackStarts.find(stackStart) != usedStackStarts.end()){
        usedStackStarts.erase(stackStart);
    }
}

uint64_t MachOMemoryManager::stackPush(uint64_t *stackTop, size_t size) {
    *stackTop -= size;
    *stackTop &= (~15);
    return *stackTop;
}

uint64_t MachOMemoryManager::stackPop(uint64_t *stackTop, size_t size) {
    *stackTop += size;
    *stackTop &= (~15);
    return *stackTop;
}


