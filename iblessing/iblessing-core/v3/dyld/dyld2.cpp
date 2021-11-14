//
//  dyld2.cpp
//  dyld2
//
//  Created by Soulghost on 2021/11/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "dyld2.hpp"
#include "dyld-sharedcache-loader.hpp"
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

static SharedCacheLoadInfo sSharedCacheLoadInfo;

void mapSharedCache(uintptr_t mainExecutableSlide) {
    SharedCacheOptions opts;
    opts.cacheDirOverride    = NULL;
    opts.forcePrivate        = false;
    opts.useHaswell          = false;
    opts.verbose             = true;
    // <rdar://problem/32031197> respect -disable_aslr boot-arg
    // <rdar://problem/56299169> kern.bootargs is now blocked
    opts.disableASLR         = mainExecutableSlide == 0;
    loadDyldCache(opts, &sSharedCacheLoadInfo);

    // update global state
    if ( sSharedCacheLoadInfo.loadAddress != nullptr ) {

    }
}

}
