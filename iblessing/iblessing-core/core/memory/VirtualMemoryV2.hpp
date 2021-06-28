//
//  VirtualMemoryV2.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/3.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef VirtualMemoryV2_hpp
#define VirtualMemoryV2_hpp

#include <vector>
#include <map>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/core/structs/Foundation.hpp>
#include <iblessing-core/core/polyfill/mach-universal.hpp>
#include <iblessing-core/core/memory/VirtualMemory.hpp>

NS_IB_BEGIN

class SymbolTable;
class ObjcRuntime;

class VirtualMemoryV2 {
public:
    VirtualMemoryV2(std::shared_ptr<VirtualMemory> fileMemory) : fileMemory(fileMemory) {
        uc = nullptr;
    }
    std::vector<std::pair<uint64_t, uint32_t>> textPatch;
    std::vector<std::pair<uint64_t, uint64_t>> dataPatch;
    
    static VirtualMemoryV2* progressDefault();
    int loadWithMachOData(std::shared_ptr<SymbolTable> symtab, std::shared_ptr<ObjcRuntime> objcRuntime, uint8_t *mappedFile);
    int mappingMachOToEngine(std::shared_ptr<SymbolTable> symtab, std::shared_ptr<ObjcRuntime> objcRuntime, uc_engine *uc, uint8_t *mappedFile);
    void relocAllRegions(std::shared_ptr<SymbolTable> symtab, std::shared_ptr<ObjcRuntime> objcRuntime, uc_engine *target = nullptr);
    uint64_t read64(uint64_t address, bool *success);
    uint32_t read32(uint64_t address, bool *success);
    bool write32(uint64_t address, uint32_t value);
    bool write64(uint64_t address, uint64_t value);
    void* readBySize(uint64_t address, uint64_t size);
    char* readString(uint64_t address, uint64_t limit);
    CFString* readAsCFString(uint64_t address, bool needCheck = true);
    char* readAsCFStringContent(uint64_t address, bool needCheck = true);
    std::pair<std::string, std::string> querySegInfo(uint64_t address);
    
    // shortcuts
    uint8_t* getMappedFile();
    std::vector<struct ib_segment_command_64 *> getSegmentHeaders();
    struct ib_section_64* getTextSect();
    struct ib_dyld_info_command* getDyldInfo();
    uint64_t getBaseAddr();
    uc_engine* getEngine();
    
private:
    VirtualMemoryV2() {};
    
protected:
    static VirtualMemoryV2 *_instance;
    std::map<uint64_t, std::pair<std::string, std::string>> addr2segInfo;
    uc_engine *uc;
    std::shared_ptr<VirtualMemory> fileMemory;
};

NS_IB_END

#endif /* VirtualMemoryV2_hpp */
