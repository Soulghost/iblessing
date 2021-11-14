//
//  dyld-sharedcache-loader.hpp
//  dyld-sharedcache-loader
//
//  Created by Soulghost on 2021/11/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef dyld_sharedcache_loader_hpp
#define dyld_sharedcache_loader_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/core/polyfill/mach-universal.hpp>
#include <iblessing-core/v3/dyld/DyldSharedCache.hpp>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>

struct SharedCacheOptions {
    const char*     cacheDirOverride;
    bool            forcePrivate;
    bool            useHaswell;
    bool            verbose;
    bool            disableASLR;
};

struct SharedCacheLoadInfo {
//    typedef const DyldSharedCache* DyldCachePtrType;
    uint64_t                     loadAddress;
    long                         slide;
    const char*                  errorMessage;
    char                         path[256];
};

struct SharedCacheFindDylibResults {
    uint64_t                    mhInCache;
    const char*                 pathInCache;
    long                        slideInCache;
};

bool loadDyldCache(uc_engine *uc, const SharedCacheOptions& options, SharedCacheLoadInfo* results);
bool findInSharedCacheImage(uc_engine *uc, const SharedCacheLoadInfo& loadInfo, const char* dylibPathToFind, SharedCacheFindDylibResults* results);

NS_IB_BEGIN

typedef struct DyldLinkContext {
    uc_engine *uc;
    SharedCacheLoadInfo loadInfo;
} DyldLinkContext;

NS_IB_END


#endif /* dyld_sharedcache_loader_hpp */
