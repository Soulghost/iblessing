//
//  HeapStackMemory.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "VirtualMemory.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include "ObjcObject.hpp"
#include <iblessing-core/v2/util/StringUtils.h>

using namespace std;
using namespace iblessing;

#define MemAssert(cond, fatal) do {\
    if (!(cond)) { \
        if (fatal) { \
            assert(false);\
        } \
        return nullptr; \
    } \
} while(0);

#define VirtualHeapLowerBound  0x300000000
#define RealHeapCopyLowerBound 0x600000000

template<typename T>
static T round_up(T address, uint64_t size) {
    if (size == 0) {
        return address;
    }
    if (address % size == 0) {
        return address;
    }
    return ((address / size) + 1) * size;
}

VirtualMemory* VirtualMemory::_instance = nullptr;

VirtualMemory* VirtualMemory::progressDefault() {
    if (VirtualMemory::_instance == nullptr) {
        VirtualMemory::_instance = new VirtualMemory();
    }
    return VirtualMemory::_instance;
}

VirtualMemory::VirtualMemory() {
    reset();
}

void VirtualMemory::storeRegister(ARM64Register *reg, uint64_t address) {
    // delete memory unit first
    if (memory.find(address) != memory.end()) {
        delete memory[address];
    }
    
    void *copyData = nullptr;
    if (reg->available) {
        copyData = malloc(reg->size);
        memcpy(copyData, reg->value, reg->size);
    }
    memory[address] = new MemoryUnit(reg->available, copyData, reg->size, "");
    
    // clear override units
    uint64_t bound = address + reg->size;
    for (uint64_t addr = address + 1; addr < bound; addr++) {
        if (memory.find(addr) != memory.end()) {
            MemoryUnit *unit = memory[addr];
            memory.erase(addr);
            delete unit;
        }
    }
}

uint64_t VirtualMemory::storeObject(void *data, uint64_t size, MemoryUnit::MemoryType type) {
    uint64_t address = round_up(heapCursor, size);
    if (memory.find(address) != memory.end()) {
        delete memory[address];
    }
    
    MemoryUnit *unit = new MemoryUnit(true, data, type, size, "");
    memory[address] = unit;
    heapCursor = address + size;
    
    if (type == MemoryUnit::MemoryType::ObjcInstance) {
        cout << termcolor::green << "[+] store ivars to memory";
        cout << termcolor::reset << endl;
        ObjcObject *obj = (ObjcObject *)data;
        Vector<ObjcIvar *> ivars = obj->isa->getAllIvars();
        for (ssize_t i = 0; i < ivars.size(); i++) {
            ObjcIvar *ivar = ivars.at(i);
            ObjcIvarObject *ivarObj = new ObjcIvarObject(ivar);
            // copy obj to real heap
            uint64_t ivarUnitAddr = heapCopyCursor;
            uint64_t ivarAddr = 0;
            if (ivar->raw.size == 8) {
                // ivar pointer
                MemoryUnit *ivarUnit = new MemoryUnit(true, ivarObj, MemoryUnit::MemoryType::ObjcIvar, 8, "");
                memory[ivarUnitAddr] = ivarUnit;
                heapCopyCursor += 8;
                ivarAddr = storeObject(new uint64_t(ivarUnitAddr), 8, MemoryUnit::MemoryType::ObjcIvar);
                
                cout << termcolor::green << "[+] store ivar pointer";
                cout << StringUtils::format(" (0x%llx) %s(type %s) at 0x%llx", ivarUnitAddr, ivar->raw.name, ivar->raw.type, ivarAddr);
                cout << termcolor::reset << endl;
            } else {
                // primary ivar
                MemoryUnit *ivarPrimaryUnit = new MemoryUnit(true, calloc(1, ivar->raw.size), MemoryUnit::MemoryType::ObjcIvarTiny, ivar->raw.size, "");
                assert(ivar->raw.size > 0);
                ivarAddr = round_up(heapCursor, ivar->raw.size);
                memory[ivarAddr] = ivarPrimaryUnit;
                heapCursor = ivarAddr + ivar->raw.size;
                
                cout << termcolor::green << "[+] store ivar";
                cout << StringUtils::format(" %s(type %s) at 0x%llx", ivar->raw.name, ivar->raw.type, ivarAddr);
                cout << termcolor::reset << endl;
            }
        }
    }
    return address;
}

bool VirtualMemory::writeBySize(void *data, uint64_t address, uint64_t size, MemoryUnit::MemoryType type) {
    // delete old unit
    if (memory.find(address) != memory.end()) {
        // FIXME: data clear
        for (uint64_t i = address; i < size; i++) {
            memory.erase(i);
        }
    }
    
    // create new unit
    MemoryUnit *unit = new MemoryUnit(true, data, type, size, "");
    memory[address] = unit;
    return true;
}

void* VirtualMemory::readBySize(uint64_t address, uint64_t size, bool fatal) {
    uint64_t realHeapLowerBound = mappedSize + vmaddr_base;
    if (address < realHeapLowerBound) {
        // FIXME: dynamic w/r in DATA
        if (address >= vmaddr_bss_start && address <= vmaddr_bss_end) {
            // bss sect
            if (memory.find(address) == memory.end()) {
                return nullptr;
            }
            
            // read bss data from heap, not file
            MemoryUnit *unit = memory[address];
            // TODO: support cross-unit read
            MemAssert(unit->size == size, fatal);
            return unit->data;
        }
        
        // external symbols first
        if (memory.find(address) != memory.end()) {
            MemoryUnit *unit = memory[address];
            // TODO: support cross-unit read
            MemAssert(unit->size == size, fatal);
            return unit->data;
        }
        
        return mappedFile + address - vmaddr_base;
    }
    
    if (address >= realHeapLowerBound && address <= VirtualHeapLowerBound) {
        // FIXME: ?
//        assert(false);
        // DATA segment
        if (memory.find(address) == memory.end()) {
            // alloc it
            void *data = malloc(size);
            bzero(data, size);
            MemoryUnit *unit = new MemoryUnit(true, data, MemoryUnit::MemoryType::Any, size, "");
            memory[address] = unit;
            return unit->data;
        } else {
            MemoryUnit *unit = memory[address];
            MemAssert(unit->size == size, fatal);
            return unit->data;
        }
    }
    
    if (memory.find(address) == memory.end()) {
        return nullptr;
    }
    
    MemoryUnit *unit = memory[address];
    // TODO: support cross-unit read
    MemAssert(unit->size == size, fatal);
    return unit->data;
}

void* VirtualMemory::readObject(uint64_t address, MemoryUnit::MemoryType type) {
    if (memory.find(address) == memory.end()) {
        return nullptr;
    }
    
    MemoryUnit *unit = memory[address];
    assert(unit->type == type);
    return unit->data;
}

char* VirtualMemory::readAsString(uint64_t address, uint64_t limit) {
    // check bss segment first
    if (address >= vmaddr_bss_start && address <= vmaddr_bss_end) {
        if (memory.find(address) != memory.end()) {
            uint64_t mem_cur = address;
            uint64_t cursize = 0;
            uint64_t maxsize = 16384;
            uint8_t *string = (uint8_t *)malloc(maxsize);
            uint8_t *string_cur = string;
            do {
                MemoryUnit *unit = memory[mem_cur];
                cursize += unit->size;
                
                // FIXME: dynamic allocate not support
                if (cursize > maxsize) {
                    assert(false);
                }
                
                memcpy(string_cur, unit->data, unit->size);
                string_cur += unit->size;
                mem_cur += unit->size;
            } while (memory.find(mem_cur) != memory.end());
            
            uint8_t *databack = (uint8_t *)malloc(cursize + 1);
            memcpy(databack, string, cursize);
            memset(databack + cursize, 0, 1);
            free(string);
            return (char *)databack;
        } else {
            return nullptr;
        }
    }
    
    uint64_t realHeapLowerBound = mappedSize + vmaddr_base;
    if (address < realHeapLowerBound) {
        return (char *)(mappedFile + address - vmaddr_base);
    }
    
    if (memory.find(address) == memory.end()) {
        return nullptr;
    }
    
    // FIXME: string read
    return nullptr;
}

char* VirtualMemory::readFromStringTable(uint64_t address) {
    return nullptr;
}

MemoryUnit* VirtualMemory::getMemoryUnit(uint64_t address) {
    if (memory.find(address) == memory.end()) {
        return nullptr;
    }
    return memory[address];
}

void VirtualMemory::reset() {
    spUpperBound = 0x00007fffffffff;
    // 2MB stack
    spLowerBound = spUpperBound - 2 * 1024 * 1024;
    
    // virtual heap
    heapCursor = VirtualHeapLowerBound;
    
    // real heap copy
    heapCopyCursor = RealHeapCopyLowerBound;
    
    memory.clear();
}

bool VirtualMemory::isMappedFileHeapForAddress(uint64_t address) {
    return address < VirtualHeapLowerBound;
}

bool VirtualMemory::isVirtualHeapForAddress(uint64_t address) {
    return address >= VirtualHeapLowerBound && address < RealHeapCopyLowerBound;
}

bool VirtualMemory::isRealHeapCopyForAddress(uint64_t address) {
    return address >= RealHeapCopyLowerBound;
}

bool VirtualMemory::isValidAddress(uint64_t address) {
    return address >= 0x100000000;
}
