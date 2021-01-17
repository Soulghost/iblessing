//
//  VirtualMemoryV2.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/3.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef VirtualMemoryV2_hpp
#define VirtualMemoryV2_hpp

#include "Foundation.hpp"
#include "mach-universal.hpp"
#include <unicorn/unicorn.h>
#include <vector>
#include <map>

NS_IB_BEGIN

class VirtualMemoryV2 {
public:
    std::vector<std::pair<uint64_t, uint32_t>> textPatch;
    std::vector<std::pair<uint64_t, uint64_t>> dataPatch;
    
    static VirtualMemoryV2* progressDefault();
    int loadWithMachOData(uint8_t *mappedFile);
    int mappingMachOToEngine(uc_engine *uc, uint8_t *mappedFile);
    void relocAllRegions(uc_engine *target = nullptr);
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
    static VirtualMemoryV2 *_instance;
    std::map<uint64_t, std::pair<std::string, std::string>> addr2segInfo;
    uc_engine *uc;
};

NS_IB_END

#endif /* VirtualMemoryV2_hpp */
