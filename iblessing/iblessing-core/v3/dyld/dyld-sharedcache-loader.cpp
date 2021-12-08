//
//  dyld-sharedcache-loader.cpp
//  dyld-sharedcache-loader
//
//  Created by Soulghost on 2021/11/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "dyld-sharedcache-loader.hpp"
#include "dyld_cache_format.h"
#include "mach-universal.hpp"
#include "MachOFile.hpp"
#include "dyld2.hpp"
#include "macho-memory.hpp"
#include "StringUtils.h"
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach/vm_prot.h>

#define ARCH_CACHE_MAGIC     "dyld_v1   arm64"

using namespace std;
using namespace iblessing;

static void rebaseChainV2(uc_engine *uc, uint64_t pageAddr, uint16_t startOffset, uintptr_t slideAmount, const dyld_cache_slide_info2* slideInfo)
{
    const uintptr_t   deltaMask    = (uintptr_t)(slideInfo->delta_mask);
    const uintptr_t   valueMask    = ~deltaMask;
    const uintptr_t   valueAdd     = (uintptr_t)(slideInfo->value_add);
    const unsigned    deltaShift   = __builtin_ctzll(deltaMask) - 2;

    uint32_t pageOffset = startOffset;
    uint32_t delta = 1;
    while ( delta != 0 ) {
        uintptr_t rawValue;
        uint64_t valueAddr = pageAddr + pageOffset;
        assert(uc_mem_read(uc, valueAddr, &rawValue, sizeof(uintptr_t)) == UC_ERR_OK);
        delta = (uint32_t)((rawValue & deltaMask) >> deltaShift);
        uintptr_t value = (rawValue & valueMask);
        if ( value != 0 ) {
            value += valueAdd;
            value += slideAmount;
        }
//        *((uintptr_t*)loc) = value;
        
        assert(uc_mem_write(uc, valueAddr, &value, sizeof(uintptr_t)) == UC_ERR_OK);
//        printf("[+] fix pointer at 0x%llx: 0x%lx-> 0x%lx\n", valueAddr, rawValue, value);
        //dyld::log("         pageOffset=0x%03X, loc=%p, org value=0x%08llX, new value=0x%08llX, delta=0x%X\n", pageOffset, loc, (uint64_t)rawValue, (uint64_t)value, delta);
        pageOffset += delta;
    }
}

static bool rebaseDataPages(uc_engine *uc, bool isVerbose, uint64_t slideInfoAddr, const dyld_cache_slide_info* slideInfo, uint64_t dataPagesStart, uint64_t sharedRegionStart, long slide) {
    const dyld_cache_slide_info* slideInfoHeader = slideInfo;
    if ( slideInfoHeader != nullptr ) {
        if ( slideInfoHeader->version == 2 ) {
            const dyld_cache_slide_info2* slideHeader = (dyld_cache_slide_info2*)slideInfo;
            const uint32_t  page_size = slideHeader->page_size;
            uint64_t page_starts_addr = slideInfoAddr + slideHeader->page_starts_offset;
            uint64_t page_extras_addr = slideInfoAddr + slideHeader->page_extras_offset;
            
            size_t page_starts_size = slideHeader->page_starts_count * sizeof(uint16_t);
            uint16_t *page_starts = (uint16_t *)malloc(page_starts_size);
            assert(uc_mem_read(uc, page_starts_addr, page_starts, page_starts_size) == UC_ERR_OK);
            
            for (int i=0; i < slideHeader->page_starts_count; ++i) {
                uint64_t pageAddr = dataPagesStart + (page_size*i);
                uint16_t pageEntry = page_starts[i];
                //dyld::log("page[%d]: page_starts[i]=0x%04X\n", i, pageEntry);
                if ( pageEntry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE )
                    continue;
                if ( pageEntry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA ) {
                    uint16_t chainIndex = (pageEntry & 0x3FFF);
                    bool done = false;
                    while ( !done ) {
                        uint64_t pageExtraAddr = page_extras_addr + chainIndex * sizeof(uint16_t);
                        uint16_t pInfo;
                        assert(uc_mem_read(uc, pageExtraAddr, &pInfo, sizeof(uint16_t)) == UC_ERR_OK);
                        uint16_t pageStartOffset = (pInfo & 0x3FFF)*4;
                        //dyld::log("     chain[%d] pageOffset=0x%03X\n", chainIndex, pageStartOffset);
                        rebaseChainV2(uc, pageAddr, pageStartOffset, slide, slideHeader);
                        done = (pInfo & DYLD_CACHE_SLIDE_PAGE_ATTR_END);
                        ++chainIndex;
                    }
                }
                else {
                    uint32_t pageOffset = pageEntry * 4;
                    //dyld::log("     start pageOffset=0x%03X\n", pageOffset);
                    rebaseChainV2(uc, pageAddr, pageOffset, slide, slideHeader);
                }
            }
        }
    } else {
        assert(false);
    }
    
    return true;
}

int __shared_region_map_and_slide_np(uc_engine *uc, int fd, uint32_t count, const ib_shared_file_mapping_np mappings[], CacheInfo info, long slide) {
    struct stat fileStatus;
    fstat(fd, &fileStatus);
    uint8_t *mappedFile = (uint8_t *)mmap(nullptr, fileStatus.st_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
    if (reinterpret_cast<int64_t>(mappedFile) == -1) {
        printf("[-] failed to open sharedcache file\n");
        assert(false);
    }
    
    for (int i = 0; i < count; i++) {
        ib_shared_file_mapping_np mapping = mappings[i];
        uc_err err = uc_mem_map(uc, mapping.sfm_address, mapping.sfm_size, mapping.sfm_init_prot & (0x7));
        if (err != UC_ERR_OK) {
            printf("[-] failed to map sharedcache region 0x%llx, size 0x%llx, prot 0x%x\n", mapping.sfm_address, mapping.sfm_size, mapping.sfm_init_prot);
            assert(false);
        } else {
            printf("[+] mapping 0x%llx - 0x%llx, with fileoff 0x%llx\n", mapping.sfm_address, mapping.sfm_address + mapping.sfm_size, mapping.sfm_file_offset);
        }
        
        err = uc_mem_write(uc, mapping.sfm_address, mappedFile + mapping.sfm_file_offset, mapping.sfm_size);
        if (err != UC_ERR_OK) {
            printf("[-] failed to write sharedcache data from fileoff 0x%llx to address 0x%llx, size 0x%llx\n", mapping.sfm_file_offset, mapping.sfm_address, mapping.sfm_size);
            assert(false);
        }
    }
    return 0;
}

int __shared_region_map_and_slide_2_np(uint32_t files_count, const ib_shared_file_np files[], uint32_t mappings_count, const ib_shared_file_mapping_slide_np mappings[]) {
    return 0;
}

static void getCachePath(const SharedCacheOptions& options, size_t pathBufferSize, char pathBuffer[])
{
    char *src = getenv("IB_SOURCE_ROOT");
    string dyldPath = StringUtils::path_join(string(src), "../dyld/iPhone10,3,iPhone10,6_14.8_18H17_Restore.dyld_shared_cache_arm64");
    const char *cachePath = dyldPath.c_str();
    assert(strlen(cachePath) + 1 < pathBufferSize);
    strcpy(pathBuffer, cachePath);
}

int openSharedCacheFile(const SharedCacheOptions& options, SharedCacheLoadInfo* results)
{
    getCachePath(options, sizeof(results->path), results->path);
    int fd = open(results->path, O_RDONLY);
    return fd;
}

static bool validMagic(const SharedCacheOptions& options, const DyldSharedCache* cache)
{
    if ( strcmp(cache->header.magic, ARCH_CACHE_MAGIC) == 0 )
        return true;
    return false;
}

static bool validPlatform(const SharedCacheOptions& options, const DyldSharedCache* cache)
{
    // grandfather in old cache that does not have platform in header
    if ( cache->header.mappingOffset < 0xE0 )
        return true;

    if ( cache->header.platform != (uint32_t)MachOFile::currentPlatform() )
        return false;

    if ( cache->header.simulator != 0 )
        return false;
    return true;
}

static bool preflightCacheFile(const SharedCacheOptions& options, SharedCacheLoadInfo* results, CacheInfo* info)
{
    
    // find and open shared cache file
    int fd = openSharedCacheFile(options, results);
    if ( fd == -1 ) {
        results->errorMessage = "shared cache file open() failed";
        return false;
    }

    struct stat cacheStatBuf;
    if ( stat(results->path, &cacheStatBuf) != 0 ) {
        results->errorMessage = "shared cache file stat() failed";
        ::close(fd);
        return false;
    }
    size_t cacheFileLength = (size_t)(cacheStatBuf.st_size);

    // sanity check header and mappings
    uint8_t firstPage[0x4000];
    if ( ::pread(fd, firstPage, sizeof(firstPage), 0) != sizeof(firstPage) ) {
        results->errorMessage = "shared cache file pread() failed";
        ::close(fd);
        return false;
    }
    const DyldSharedCache* cache = (DyldSharedCache*)firstPage;
    if ( !validMagic(options, cache) ) {
        results->errorMessage = "shared cache file has wrong magic";
        ::close(fd);
        return false;
    }
    if ( !validPlatform(options, cache) ) {
        results->errorMessage = "shared cache file is for a different platform";
        ::close(fd);
        return false;
    }
    if ( (cache->header.mappingCount < 3) || (cache->header.mappingCount > DyldSharedCache::MaxMappings) || (cache->header.mappingOffset > 0x168) ) {
        results->errorMessage = "shared cache file mappings are invalid";
        ::close(fd);
        return false;
    }
    const dyld_cache_mapping_info* const fileMappings = (dyld_cache_mapping_info*)&firstPage[cache->header.mappingOffset];
    const dyld_cache_mapping_info* textMapping = &fileMappings[0];
    const dyld_cache_mapping_info* firstDataMapping = &fileMappings[1];
    const dyld_cache_mapping_info* linkeditMapping = &fileMappings[cache->header.mappingCount - 1];
    if (  (textMapping->fileOffset != 0)
      || ((fileMappings[0].address + fileMappings[0].size) > firstDataMapping->address)
      || ((fileMappings[0].fileOffset + fileMappings[0].size) != firstDataMapping->fileOffset)
      || ((cache->header.codeSignatureOffset + cache->header.codeSignatureSize) != cacheFileLength)
      || (textMapping->maxProt != (VM_PROT_READ | VM_PROT_EXECUTE))
      || (linkeditMapping->maxProt != VM_PROT_READ) ) {
        results->errorMessage = "shared cache text/linkedit mappings are invalid";
        ::close(fd);
        return false;
    }

    // Check the __DATA mappings
    for (unsigned i = 1; i != (cache->header.mappingCount - 1); ++i) {
        if ( ((fileMappings[i].address + fileMappings[i].size) > fileMappings[i + 1].address)
          || ((fileMappings[i].fileOffset + fileMappings[i].size) != fileMappings[i + 1].fileOffset)
          || (fileMappings[i].maxProt != (VM_PROT_READ|VM_PROT_WRITE)) ) {
            results->errorMessage = "shared cache data mappings are invalid";
            ::close(fd);
            return false;
        }
    }

    if ( (textMapping->address != cache->header.sharedRegionStart) || ((linkeditMapping->address + linkeditMapping->size) > (cache->header.sharedRegionStart+cache->header.sharedRegionSize)) ) {
        results->errorMessage = "shared cache file mapping addressses invalid";
        ::close(fd);
        return false;
    }

    // register code signature of cache file
    fsignatures_t siginfo;
    siginfo.fs_file_start = 0;  // cache always starts at beginning of file
    siginfo.fs_blob_start = (void*)cache->header.codeSignatureOffset;
    siginfo.fs_blob_size  = (size_t)(cache->header.codeSignatureSize);
    int result = fcntl(fd, F_ADDFILESIGS_RETURN, &siginfo);
    if ( result == -1 ) {
        results->errorMessage = "code signature registration for shared cache failed";
        ::close(fd);
        return false;
    }

    // <rdar://problem/23188073> validate code signature covers entire shared cache
    uint64_t codeSignedLength = siginfo.fs_file_start;
    if ( codeSignedLength < cache->header.codeSignatureOffset ) {
        results->errorMessage = "code signature does not cover entire shared cache file";
        ::close(fd);
        return false;
    }
    void* mappedData = ::mmap(NULL, sizeof(firstPage), PROT_READ|PROT_EXEC, MAP_PRIVATE, fd, 0);
    if ( mappedData == MAP_FAILED ) {
        results->errorMessage = "first page of shared cache not mmap()able";
        ::close(fd);
        return false;
    }
    if ( memcmp(mappedData, firstPage, sizeof(firstPage)) != 0 ) {
        results->errorMessage = "first page of mmap()ed shared cache not valid";
        ::close(fd);
        return false;
    }
    ::munmap(mappedData, sizeof(firstPage));

    // fill out results
    info->mappingsCount = cache->header.mappingCount;
    // We have to emit the mapping for the __LINKEDIT before the slid mappings
    // This is so that the kernel has already mapped __LINKEDIT in to its address space
    // for when it copies the slid info for each __DATA mapping
    for (int i=0; i < cache->header.mappingCount; ++i) {
        uint64_t    slideInfoFileOffset = 0;
        uint64_t    slideInfoFileSize   = 0;
        vm_prot_t   authProt            = 0;
        vm_prot_t   initProt            = fileMappings[i].initProt;
        if ( cache->header.mappingOffset <= __offsetof(dyld_cache_header, mappingWithSlideOffset) ) {
            // Old cache without the new slid mappings
            if ( i == 1 ) {
                // Add slide info to the __DATA mapping
                slideInfoFileOffset = cache->header.slideInfoOffsetUnused;
                slideInfoFileSize   = cache->header.slideInfoSizeUnused;
                // Don't set auth prot to anything interseting on the old mapppings
                authProt = 0;
            }
        } else {
            // New cache where each mapping has a corresponding slid mapping
            const dyld_cache_mapping_and_slide_info* slidableMappings = (const dyld_cache_mapping_and_slide_info*)&firstPage[cache->header.mappingWithSlideOffset];
            slideInfoFileOffset = slidableMappings[i].slideInfoFileOffset;
            slideInfoFileSize   = slidableMappings[i].slideInfoFileSize;
            if ( (slidableMappings[i].flags & DYLD_CACHE_MAPPING_AUTH_DATA) == 0 )
                authProt = IB_VM_PROT_NOAUTH;
            if ( (slidableMappings[i].flags & DYLD_CACHE_MAPPING_CONST_DATA) != 0 ) {
                // The cache was built with __DATA_CONST being read-only.  We can override that
                initProt |= VM_PROT_WRITE;
            }
        }

        // Add a file for each mapping
        info->fd                        = fd;
        info->mappings[i].sms_address               = fileMappings[i].address;
        info->mappings[i].sms_size                  = fileMappings[i].size;
        info->mappings[i].sms_file_offset           = fileMappings[i].fileOffset;
        info->mappings[i].sms_slide_size            = 0;
        info->mappings[i].sms_slide_start           = 0;
        info->mappings[i].sms_max_prot              = fileMappings[i].maxProt;
        info->mappings[i].sms_init_prot             = initProt;
        if ( slideInfoFileSize != 0 ) {
            uint64_t offsetInLinkEditRegion = (slideInfoFileOffset - linkeditMapping->fileOffset);
            info->mappings[i].sms_slide_start   = (user_addr_t)(linkeditMapping->address + offsetInLinkEditRegion);
            info->mappings[i].sms_slide_offset   = slideInfoFileOffset;
            info->mappings[i].sms_slide_size    = (user_addr_t)slideInfoFileSize;
            info->mappings[i].sms_init_prot    |= (IB_VM_PROT_SLIDE | authProt);
            info->mappings[i].sms_max_prot     |= (IB_VM_PROT_SLIDE | authProt);
        }
    }
    info->sharedRegionStart = cache->header.sharedRegionStart;
    info->sharedRegionSize  = cache->header.sharedRegionSize;
    info->maxSlide          = cache->header.maxSlide;
    return true;
}

static bool reuseExistingCache(const SharedCacheOptions& options, SharedCacheLoadInfo* results) {
    return false;
}

static void verboseSharedCacheMappings(const ib_shared_file_mapping_slide_np mappings[DyldSharedCache::MaxMappings],
                                       uint32_t mappingsCount)
{
    for (int i=0; i < mappingsCount; ++i) {
        const char* mappingName = "";
        if ( mappings[i].sms_max_prot & VM_PROT_WRITE ) {
            if ( mappings[i].sms_max_prot & IB_VM_PROT_NOAUTH ) {
                // __DATA*
                mappingName = "data";
            } else {
                // __AUTH*
                mappingName = "auth";
            }
        }
        uint32_t init_prot = mappings[i].sms_init_prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        uint32_t max_prot = mappings[i].sms_max_prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        dyld::log("        0x%08llX->0x%08llX init=%x, max=%x %s%s%s%s\n",
            mappings[i].sms_address, mappings[i].sms_address+mappings[i].sms_size-1,
            init_prot, max_prot,
            ((mappings[i].sms_init_prot & VM_PROT_READ) ? "read " : ""),
            ((mappings[i].sms_init_prot & VM_PROT_WRITE) ? "write " : ""),
            ((mappings[i].sms_init_prot & VM_PROT_EXECUTE) ? "execute " : ""),
            mappingName);
    }
}

static void verboseSharedCacheMappingsToConsole(const ib_shared_file_mapping_slide_np mappings[DyldSharedCache::MaxMappings],
                                                uint32_t mappingsCount)
{
    for (int i=0; i < mappingsCount; ++i) {
        const char* mappingName = "";
        if ( mappings[i].sms_max_prot & VM_PROT_WRITE ) {
            if ( mappings[i].sms_max_prot & IB_VM_PROT_NOAUTH ) {
                // __DATA*
                mappingName = "data";
            } else {
                // __AUTH*
                mappingName = "auth";
            }
        }
        uint32_t init_prot = mappings[i].sms_init_prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        uint32_t max_prot = mappings[i].sms_max_prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        dyld::logToConsole("dyld: mapping 0x%08llX->0x%08llX init=%x, max=%x %s%s%s%s\n",
                           mappings[i].sms_address, mappings[i].sms_address+mappings[i].sms_size-1,
                           init_prot, max_prot,
                           ((mappings[i].sms_init_prot & VM_PROT_READ) ? "read " : ""),
                           ((mappings[i].sms_init_prot & VM_PROT_WRITE) ? "write " : ""),
                           ((mappings[i].sms_init_prot & VM_PROT_EXECUTE) ? "execute " : ""),
                           mappingName);
    }
}

static long pickCacheASLRSlide(CacheInfo& info)
{
    // choose new random slide
    // <rdar://problem/20848977> change shared cache slide for 32-bit arm to always be 16k aligned
    long slide;
    if (info.maxSlide == 0)
        slide = 0;
    else
        slide = ((arc4random() % info.maxSlide) & (-16384));
    return slide;
}

static bool mapCacheSystemWide(uc_engine *uc, const SharedCacheOptions& options, SharedCacheLoadInfo* results)
{
    CacheInfo info;
    if ( !preflightCacheFile(options, results, &info) ) {
        return false;
    }
    results->info = info;
    int result = 0;
    if ( info.mappingsCount != 3 ) {
        // FIXME: unimpl A12+ sharedcache mapping
        assert(false);
        uint32_t maxSlide = options.disableASLR ? 0 : (uint32_t)info.maxSlide;

        ib_shared_file_np file;
        file.sf_fd = info.fd;
        file.sf_mappings_count = info.mappingsCount;
        // For the new syscall, this is actually the max slide.  The kernel now owns the actual slide
        file.sf_slide = maxSlide;
        result = __shared_region_map_and_slide_2_np(1, &file, info.mappingsCount, info.mappings);
    } else {
        // With the old syscall, dyld has to choose the slide
        results->slide = options.disableASLR ? 0 : pickCacheASLRSlide(info);

        // update mappings based on the slide we choose
        for (uint32_t i=0; i < info.mappingsCount; ++i) {
            info.mappings[i].sms_address += results->slide;
            if ( info.mappings[i].sms_slide_size != 0 )
                info.mappings[i].sms_slide_start += (uint32_t)results->slide;
        }

        // If we get here then we don't have the new kernel function, so use the old one
        ib_shared_file_mapping_np mappings[3];
        for (unsigned i = 0; i != 3; ++i) {
            mappings[i].sfm_address         = info.mappings[i].sms_address;
            mappings[i].sfm_size            = info.mappings[i].sms_size;
            mappings[i].sfm_file_offset     = info.mappings[i].sms_file_offset;
            mappings[i].sfm_max_prot        = info.mappings[i].sms_max_prot;
            mappings[i].sfm_init_prot       = info.mappings[i].sms_init_prot;
        }
        result = __shared_region_map_and_slide_np(uc, info.fd, 3, mappings, info, results->slide);
    }

    close(info.fd);
    if ( result == 0 ) {
        results->loadAddress = info.mappings[0].sms_address;
        if ( info.mappingsCount != 3 ) {
            assert(false);
            // We don't know our own slide any more as the kernel owns it, so ask for it again now
            if ( reuseExistingCache(options, results) ) {

                // update mappings based on the slide the kernel chose
                for (uint32_t i=0; i < info.mappingsCount; ++i) {
                    info.mappings[i].sms_address += results->slide;
                    if ( info.mappings[i].sms_slide_size != 0 )
                        info.mappings[i].sms_slide_start += (uint32_t)results->slide;
                }

                if ( options.verbose )
                    verboseSharedCacheMappingsToConsole(info.mappings, info.mappingsCount);
                return true;
            }
            // Uh oh, we mapped the kernel, but we didn't find the slide
            if ( options.verbose )
                dyld::logToConsole("dyld: error finding shared cache slide for system wide mapping\n");
            return false;
        }
    }
    else {
        // could be another process beat us to it
        if ( reuseExistingCache(options, results) )
            return true;
        // if cache does not exist, then really is an error
        if ( results->errorMessage == nullptr )
            results->errorMessage = "syscall to map cache into shared region failed";
        return false;
    }

    if ( options.verbose ) {
        dyld::log("mapped dyld cache file system wide: %s\n", results->path);
        verboseSharedCacheMappings(info.mappings, info.mappingsCount);
    }
    
    // do rebase?
    // rebase slide
    for (int i = 0; i < info.mappingsCount; i++) {
        if ( info.mappings[i].sms_slide_size == 0 ) {
            continue;
        }
        
        struct dyld_cache_slide_info2 *slideInfo = (struct dyld_cache_slide_info2 *)malloc(sizeof(struct dyld_cache_slide_info2));
        assert(uc_mem_read(uc, info.mappings[i].sms_slide_start, slideInfo, sizeof(struct dyld_cache_slide_info2)) == UC_ERR_OK);
        assert(slideInfo->version == 2);
        rebaseDataPages(uc, true, info.mappings[i].sms_slide_start, (dyld_cache_slide_info *)slideInfo, info.mappings[i].sms_address, info.sharedRegionStart, results->slide);
        free(slideInfo);
    }
    return true;
}

bool loadDyldCache(uc_engine *uc, const SharedCacheOptions& options, SharedCacheLoadInfo* results)
{
    results->loadAddress        = 0;
    results->slide              = 0;
    results->errorMessage       = nullptr;

    if ( options.forcePrivate ) {
        // mmap cache into this process only
        assert(false);
    }
    else {
        // fast path: when cache is already mapped into shared region
        bool hasError = false;
        if ( reuseExistingCache(options, results) ) {
            hasError = (results->errorMessage != nullptr);
        } else {
            // slow path: this is first process to load cache
            hasError = mapCacheSystemWide(uc, options, results);
        }
        return hasError;
    }
}

bool findInSharedCacheImage(uc_engine *uc, const SharedCacheLoadInfo& loadInfo, const char* dylibPathToFind, SharedCacheFindDylibResults* results)
{
    if ( loadInfo.loadAddress == 0 )
        return false;

    // support for older cache with a different Image* format
    uint64_t hash = 0;
    for (const char* s=dylibPathToFind; *s != '\0'; ++s)
            hash += hash*4 + *s;
    
    dyld_cache_header header;
    assert(uc_mem_read(uc, loadInfo.loadAddress, &header, sizeof(dyld_cache_header)) == UC_ERR_OK);
    uint64_t imageInfoAddress = loadInfo.loadAddress + header.imagesOffset;
    uint64_t imageInfoCount = header.imagesCount;
    
    while (imageInfoCount--) {
        dyld_cache_image_info info;
        assert(uc_mem_read(uc, imageInfoAddress, &info, sizeof(dyld_cache_image_info)) == UC_ERR_OK);
        dyld_cache_image_info *p = &info;
        
        // FIXME: hash compare failed?
        // on iOS, inode is used to hold hash of path
//        if ( (p->modTime == 0) && (p->inode != hash) )
//            continue;
        uint64_t aPathAddr = loadInfo.loadAddress + p->pathFileOffset;
        char* aPath = MachoMemoryUtils::uc_read_string(uc, aPathAddr, 1000);
//        printf("[+] path %s\n", aPath);
        assert(aPath != NULL);
        if ( strcmp(aPath, dylibPathToFind) == 0 ) {
            results->mhInCache    = p->address+loadInfo.slide;
            results->pathInCache  = strdup(aPath);
            results->slideInCache = loadInfo.slide;
            free(aPath);
            return true;
        }
        free(aPath);
        imageInfoAddress += sizeof(dyld_cache_image_info);
    }
    return false;
}
