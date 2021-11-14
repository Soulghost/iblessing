//
//  dyld-sharedcache-loader.hpp
//  dyld-sharedcache-loader
//
//  Created by Soulghost on 2021/11/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef dyld_sharedcache_loader_hpp
#define dyld_sharedcache_loader_hpp

#include <iblessing-core/v3/dyld/DyldSharedCache.hpp>

struct SharedCacheOptions {
    const char*     cacheDirOverride;
    bool            forcePrivate;
    bool            useHaswell;
    bool            verbose;
    bool            disableASLR;
};

struct SharedCacheLoadInfo {
    typedef const DyldSharedCache* DyldCachePtrType;
    DyldCachePtrType             loadAddress;
    long                         slide;
    const char*                  errorMessage;
    char                         path[256];
};

bool loadDyldCache(const SharedCacheOptions& options, SharedCacheLoadInfo* results);

#endif /* dyld_sharedcache_loader_hpp */
