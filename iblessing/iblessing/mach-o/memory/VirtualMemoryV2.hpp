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

NS_IB_BEGIN

class VirtualMemoryV2 {
public:
    static VirtualMemoryV2* progressDefault();
    
    int loadWithMachOData(uint8_t *mappedFile);
    int mappingMachOToEngine(uc_engine *uc, uint8_t *mappedFile);
    uint64_t read64(uint64_t address, bool *success);
    uint32_t read32(uint64_t address, bool *success);
    void* readBySize(uint64_t address, uint64_t size);
    char* readString(uint64_t address, uint64_t limit);
    CFString* readAsCFString(uint64_t address, bool needCheck = true);
    char* readAsCFStringContent(uint64_t address, bool needCheck = true);
    
    // shortcuts
    uint8_t* getMappedFile();
    std::vector<struct ib_segment_command_64 *> getSegmentHeaders();
    struct ib_section_64* getTextSect();
    struct ib_dyld_info_command* getDyldInfo();
    
    
private:
    static VirtualMemoryV2 *_instance;
    uc_engine *uc;
};

NS_IB_END

#endif /* VirtualMemoryV2_hpp */
