//
//  dyld2.cpp
//  dyld2
//
//  Created by Soulghost on 2021/11/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "dyld2.hpp"
#include <stdarg.h>

namespace dyld {

void log(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vdprintf(1, format, list);
    va_end(list);
}

void logToConsole(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vdprintf(1, format, list);
    va_end(list);
}

SharedCacheLoadInfo mapSharedCache(uc_engine *uc, uintptr_t mainExecutableSlide) {
    SharedCacheLoadInfo sSharedCacheLoadInfo;
    SharedCacheOptions opts;
    opts.cacheDirOverride    = NULL;
    opts.forcePrivate        = false;
    opts.useHaswell          = false;
    opts.verbose             = true;
    // <rdar://problem/32031197> respect -disable_aslr boot-arg
    // <rdar://problem/56299169> kern.bootargs is now blocked
    opts.disableASLR         = mainExecutableSlide == 0;
    loadDyldCache(uc, opts, &sSharedCacheLoadInfo);

    // update global state
    if ( sSharedCacheLoadInfo.loadAddress != 0 ) {

    }
    return sSharedCacheLoadInfo;
}

}
