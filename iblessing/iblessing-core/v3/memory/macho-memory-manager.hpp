//
//  macho-memory-manager.hpp
//  macho-memory-manager
//
//  Created by Soulghost on 2021/10/17.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef macho_memory_manager_hpp
#define macho_memory_manager_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>

NS_IB_BEGIN

class MachOMemoryManager {
public:
    MachOMemoryManager(uc_engine *uc);
    
    uint64_t alloc(size_t size, std::string tag = "");
    void free(uint64_t addr);
    
private:
    uc_engine *uc;
    uint64_t allocatedCur;
    uint64_t allocateBegin;
    uint64_t allocateEnd;
};

NS_IB_END

#endif /* macho_memory_manager_hpp */
