//
//  macho-memory.hpp
//  iblessing-core
//
//  Created by soulghost on 2021/9/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef macho_memory_hpp
#define macho_memory_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>

NS_IB_BEGIN

namespace MachoMemoryUtils {
    char* uc_read_string(uc_engine *uc, uint64_t address, uint64_t limit);
};

NS_IB_END

#endif /* macho_memory_hpp */
