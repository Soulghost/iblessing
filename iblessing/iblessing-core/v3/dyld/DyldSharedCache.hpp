//
//  DyldSharedCache.hpp
//  DyldSharedCache
//
//  Created by Soulghost on 2021/11/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef DyldSharedCache_hpp
#define DyldSharedCache_hpp

#include <stdio.h>
#include <iblessing-core/v3/dyld/dyld_cache_format.h>

class DyldSharedCache {
public:
    dyld_cache_header header;

    // The most mappings we could generate.
    // For now its __TEXT, __DATA_CONST, __DATA_DIRTY, __DATA, __LINKEDIT,
    // and optionally also __AUTH, __AUTH_CONST, __AUTH_DIRTY
    static const uint32_t MaxMappings = 8;
};

#endif /* DyldSharedCache_hpp */
