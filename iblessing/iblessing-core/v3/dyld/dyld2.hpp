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
#include <iblessing-core/v3/mach-o/macho-module.hpp>

namespace dyld {
    extern void log(const char*, ...);
    extern void logToConsole(const char* format, ...);
    extern SharedCacheLoadInfo mapSharedCache(uc_engine *uc, uintptr_t mainExecutableSlide);
    uint64_t dlsym_internal(std::shared_ptr<iblessing::MachOLoader> loader, int64_t handle, uint64_t symbolAddr, uint64_t callerAddress);
}

#endif /* dyld2_hpp */
