//
//  uc_debugger_utils.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/10/5.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "uc_debugger_utils.hpp"

void print_uc_mem_regions(uc_engine *uc) {
    uc_mem_region *regions;
    uint32_t count;
    assert(uc_mem_regions(uc, &regions, &count) == UC_ERR_OK);
    uc_mem_region *region_cur = regions;
    while (count--) {
        printf("[Stalker][*] memory region 0x%llx - 0x%llx (size=0x%llx), prot %d\n", region_cur->begin, region_cur->end, region_cur->end - region_cur->begin, region_cur->perms);
        region_cur += 1;
    }
    free(regions);
}
