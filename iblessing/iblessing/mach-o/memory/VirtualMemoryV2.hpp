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
#include <unicorn/unicorn.h>

NS_IB_BEGIN

class VirtualMemoryV2 {
public:
    static VirtualMemoryV2* progressDefault();
    
    int loadWithMachOData(uint8_t *mappedFile);
    uint64_t read64(uint64_t address, bool *success);
    uint32_t read32(uint64_t address, bool *success);
    char* readString(uint64_t address, uint64_t limit);
    CFString* readAsCFString(uint64_t address, bool needCheck = true);
    char* readAsCFStringContent(uint64_t address, bool needCheck = true);
    
private:
    static VirtualMemoryV2 *_instance;
    uc_engine *uc;
};

NS_IB_END

#endif /* VirtualMemoryV2_hpp */
