//
//  macho-memory-manager.cpp
//  macho-memory-manager
//
//  Created by Soulghost on 2021/10/17.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "macho-memory-manager.hpp"
#include "mach-universal.hpp"
#include "uc_debugger_utils.hpp"

extern "C" {
#include <sys/types.h>
#include <sys/mman.h>
#include <mach/mach.h>
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
    if (size == 0) {
        size = 1;
    }
    
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

void MachOMemoryManager::dealloc(uint64_t addr) {
    if(use_shared && (addr < allocateBegin || addr >= allocateEnd)){
        free((void *)addr);
    }
}

void *MachOMemoryManager::mmapWrapper(uint64_t guest_addr, size_t size, int prot, int flags, int fd, off_t off) {
    
    uint64_t guest_addr_rounded = (guest_addr / 0x4000) * 0x4000;
    if(guest_addr != guest_addr_rounded){
        size += guest_addr - guest_addr_rounded;
    }
    size_t size_rounded = ROUNDUP(size, 0x4000);
    
    if (guest_addr_rounded == 0) {
        guest_addr_rounded = 0x400000000;
    }
    void *mmaped_addr = mmap((void *)guest_addr_rounded, size_rounded, prot, flags, fd, off);
//    assert(!guest_addr_rounded || mmaped_addr == (void *)guest_addr_rounded);
    uc_err uc_map_err = uc_mem_map_ptr(uc, (uint64_t)mmaped_addr, size_rounded, prot, mmaped_addr);
    if (uc_map_err != UC_ERR_OK) {
        print_uc_mem_regions(uc);
        uc_debug_print_backtrace(uc);
        assert(false);
    }
    return mmaped_addr;

}

void *MachOMemoryManager::mmapSharedMem(uint64_t guest_addr, size_t size, int prot) {
    int flags = MAP_PRIVATE|MAP_ANONYMOUS;
    if(guest_addr){
        flags |= MAP_FIXED;
    }
    return mmapWrapper(guest_addr, size, prot, flags, -1, 0);
}

void *MachOMemoryManager::consumeMmapRegion(uint64_t start_addr, uint64_t size, int prot) {
    return mmap((void *)start_addr, size, prot, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
}

uint64_t MachOMemoryManager::stackNew() {
    // stack FIXME: single stack
    return stackEnd;
    
//    uint64_t newStackAddr = stackEnd;
//    bool found = false;
//    while(newStackAddr < stackEnd){
//        if(usedStackStarts.find(newStackAddr) == usedStackStarts.end()){
//            found = true;
//            usedStackStarts.insert(newStackAddr);
//            break;
//        }
//        newStackAddr += IB_STACK_SIZE;
//    }
//    if(found){
//        return newStackAddr;
//    }else{
//        return NULL;
//    }
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


