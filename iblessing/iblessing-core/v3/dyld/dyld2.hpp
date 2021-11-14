//
//  dyld2.hpp
//  dyld2
//
//  Created by Soulghost on 2021/11/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef dyld2_hpp
#define dyld2_hpp

#include <stdio.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include "dyld-sharedcache-loader.hpp"

namespace dyld {
    extern void log(const char*, ...);
    extern void logToConsole(const char* format, ...);
    extern SharedCacheLoadInfo mapSharedCache(uc_engine *uc, uintptr_t mainExecutableSlide);
}

#endif /* dyld2_hpp */
