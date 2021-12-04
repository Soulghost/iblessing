//
//  dyld_images.h
//  dyld_images
//
//  Created by Soulghost on 2021/12/3.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef dyld_images_h
#define dyld_images_h

enum dyld_image_mode { dyld_image_adding=0, dyld_image_removing=1, dyld_image_info_change=2 };

struct dyld_image_info {
    const struct mach_header*    imageLoadAddress;    /* base address image is mapped into */
    const char*                    imageFilePath;        /* path dyld used to load the image */
    uintptr_t                    imageFileModDate;    /* time_t of image file */
                                                    /* if stat().st_mtime of imageFilePath does not match imageFileModDate, */
                                                    /* then file has been modified since dyld loaded it */
};

struct dyld_uuid_info {
    const struct mach_header*    imageLoadAddress;    /* base address image is mapped into */
    uuid_t                        imageUUID;            /* UUID of image */
};

#define DYLD_AOT_IMAGE_KEY_SIZE 32
struct dyld_aot_image_info {
    const struct mach_header*   x86LoadAddress;
    const struct mach_header*   aotLoadAddress;
    uint64_t                    aotImageSize;
    uint8_t                     aotImageKey[DYLD_AOT_IMAGE_KEY_SIZE]; // uniquely identifying SHA-256 key for this aot
};

struct dyld_aot_shared_cache_info {
    const uintptr_t cacheBaseAddress;
    uuid_t          cacheUUID;
};

typedef void (*dyld_image_notifier)(enum dyld_image_mode mode, uint32_t infoCount, const struct dyld_image_info info[]);

/* for use in dyld_all_image_infos.errorKind field */
enum {    dyld_error_kind_none=0,
        dyld_error_kind_dylib_missing=1,
        dyld_error_kind_dylib_wrong_arch=2,
        dyld_error_kind_dylib_version=3,
        dyld_error_kind_symbol_missing=4
    };

/* internal limit */
#define DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT  8

struct dyld_all_image_infos {
    uint32_t                        version;        /* 1 in Mac OS X 10.4 and 10.5 */
    uint32_t                        infoArrayCount;
#if defined(__cplusplus) && (BUILDING_LIBDYLD || BUILDING_DYLD)
    std::atomic<const struct dyld_image_info*>    infoArray;
#else
    const struct dyld_image_info*    infoArray;
#endif
    dyld_image_notifier                notification;
    bool                            processDetachedFromSharedRegion;
    /* the following fields are only in version 2 (Mac OS X 10.6, iPhoneOS 2.0) and later */
    bool                            libSystemInitialized;
    const struct mach_header*        dyldImageLoadAddress;
    /* the following field is only in version 3 (Mac OS X 10.6, iPhoneOS 3.0) and later */
    void*                            jitInfo;
    /* the following fields are only in version 5 (Mac OS X 10.6, iPhoneOS 3.0) and later */
    const char*                        dyldVersion;
    const char*                        errorMessage;
    uintptr_t                        terminationFlags;
    /* the following field is only in version 6 (Mac OS X 10.6, iPhoneOS 3.1) and later */
    void*                            coreSymbolicationShmPage;
    /* the following field is only in version 7 (Mac OS X 10.6, iPhoneOS 3.1) and later */
    uintptr_t                        systemOrderFlag;
    /* the following field is only in version 8 (Mac OS X 10.7, iPhoneOS 3.1) and later */
    uintptr_t                        uuidArrayCount;
    const struct dyld_uuid_info*    uuidArray;        /* only images not in dyld shared cache */
    /* the following field is only in version 9 (Mac OS X 10.7, iOS 4.0) and later */
    struct dyld_all_image_infos*    dyldAllImageInfosAddress;
    /* the following field is only in version 10 (Mac OS X 10.7, iOS 4.2) and later */
    uintptr_t                        initialImageCount;
    /* the following field is only in version 11 (Mac OS X 10.7, iOS 4.2) and later */
    uintptr_t                        errorKind;
    const char*                        errorClientOfDylibPath;
    const char*                        errorTargetDylibPath;
    const char*                        errorSymbol;
    /* the following field is only in version 12 (Mac OS X 10.7, iOS 4.3) and later */
    uintptr_t                        sharedCacheSlide;
    /* the following field is only in version 13 (Mac OS X 10.9, iOS 7.0) and later */
    uint8_t                            sharedCacheUUID[16];
    /* the following field is only in version 15 (macOS 10.12, iOS 10.0) and later */
    uintptr_t                        sharedCacheBaseAddress;
#if defined(__cplusplus) && (BUILDING_LIBDYLD || BUILDING_DYLD)
    // We want this to be atomic in libdyld so that we can see updates when we map it shared
    std::atomic<uint64_t>           infoArrayChangeTimestamp;
#else
    uint64_t                        infoArrayChangeTimestamp;
#endif
    const char*                        dyldPath;
    mach_port_t                        notifyPorts[DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT];
#if __LP64__
    uintptr_t                        reserved[11-(DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT/2)];
#else
    uintptr_t                        reserved[9-DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT];
#endif
    // The following fields were added in version 18 (previously they were reserved padding fields)
    uint64_t                        sharedCacheFSID;
    uint64_t                        sharedCacheFSObjID;
    /* the following field is only in version 16 (macOS 10.13, iOS 11.0) and later */
    uintptr_t                       compact_dyld_image_info_addr;
    size_t                          compact_dyld_image_info_size;
    uint32_t                        platform; // FIXME: really a dyld_platform_t, but those aren't exposed here.

    /* the following field is only in version 17 (macOS 10.16) and later */
    uint32_t                          aotInfoCount;
    const struct dyld_aot_image_info* aotInfoArray;
    uint64_t                          aotInfoArrayChangeTimestamp;
    uintptr_t                         aotSharedCacheBaseAddress;
    uint8_t                           aotSharedCacheUUID[16];
};

#endif /* dyld_images_h */
