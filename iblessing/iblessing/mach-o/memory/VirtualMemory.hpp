//
//  HeapStackMemory.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef HeapStackMemory_hpp
#define HeapStackMemory_hpp

#include "Object.hpp"
#include <unordered_map>
#include "ARM64Registers.hpp"
#include <vector>
#include <mach-o/loader.h>

NS_IB_BEGIN

class MemoryUnit {
public:
    typedef enum MemoryType {
        Common = 0,
        ObjcClass,
        ObjcInstance,
        ObjcIvar,
        ObjcIvarTiny,
        Any
    } MemoryType;
    
    bool available;
    void *data;
    uint64_t size;
    MemoryType type;
    std::string comment;
    
    MemoryUnit(bool available, void *data, uint64_t size, std::string comment):
        MemoryUnit(available, data, Common, size, comment) {}
    
    MemoryUnit(bool available, void *data, MemoryType type, uint64_t size, std::string comment):
        available(available),
        data(data),
        type(type),
        size(size),
        comment(comment) {}
};

class VirtualMemory {
public:
    static VirtualMemory* progressDefault();
    
    uint64_t spUpperBound;
    uint64_t spLowerBound;
    uint64_t heapCursor;
    uint64_t heapCopyCursor;
    
    // file
    uint8_t *mappedFile;
    uint64_t mappedSize;
    // vmaddr base
    uint64_t vmaddr_base;
    // symtab、dlsymtab、strtab's vmaddr base on LINKEDIT's vmaddr
    uint64_t linkedit_base;
    // bss
    uint64_t vmaddr_bss_start;
    uint64_t vmaddr_bss_end;
    
    // extra info
    std::vector<struct segment_command_64 *> segmentHeaders;
    dyld_info_command *dyldinfo;
    struct segment_command_64 *textSeg;
    struct section_64 *textSect;
    
    void storeRegister(ARM64Register *reg, uint64_t address);
    uint64_t storeObject(void *data, uint64_t size, MemoryUnit::MemoryType type);
    bool writeBySize(void *data, uint64_t address, uint64_t size, MemoryUnit::MemoryType type);
    void* readBySize(uint64_t address, uint64_t size, bool fatal = true);
    void* readObject(uint64_t address, MemoryUnit::MemoryType type);
    char* readAsString(uint64_t address, uint64_t limit);
    char* readFromStringTable(uint64_t address);
    MemoryUnit* getMemoryUnit(uint64_t address);
    void reset();
    
    bool isMappedFileHeapForAddress(uint64_t address);
    bool isVirtualHeapForAddress(uint64_t address);
    bool isRealHeapCopyForAddress(uint64_t address);
    bool isValidAddress(uint64_t address);
    
protected:
    VirtualMemory();
    
private:
    static VirtualMemory *_instance;
    std::unordered_map<uint64_t, MemoryUnit *> memory;
};

NS_IB_END

#endif /* HeapStackMemory_hpp */
