//
//  mach-universal.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/9.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "mach-universal.hpp"
#include <cassert>

void ib_swap_mach_header_64(struct ib_mach_header_64 *mh, enum IBByteOrder target_byte_order) {
    assert(false);
}

void ib_swap_fat_header(struct ib_fat_header *mh, enum IBByteOrder target_byte_order) {
    mh->magic = __builtin_bswap32(mh->magic);
    mh->nfat_arch = __builtin_bswap32(mh->nfat_arch);
}

void ib_swap_fat_arch(struct ib_fat_arch *arch, enum IBByteOrder target_byte_order) {
    arch->cputype = __builtin_bswap32(arch->cputype);
    arch->cpusubtype = __builtin_bswap32(arch->cpusubtype);
    arch->offset = __builtin_bswap32(arch->offset);
    arch->size = __builtin_bswap32(arch->size);
    arch->align = __builtin_bswap32(arch->align);
}
