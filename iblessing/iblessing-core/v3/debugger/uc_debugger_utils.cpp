//
//  uc_debugger_utils.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/10/5.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "uc_debugger_utils.hpp"
#include "buffered_logger.hpp"
#include <map>

using namespace std;
using namespace iblessing;

static map<uc_engine *, set<uint64_t>> breakpointMap;

void print_uc_mem_regions(uc_engine *uc) {
    uc_mem_region *regions;
    uint32_t count;
    assert(uc_mem_regions(uc, &regions, &count) == UC_ERR_OK);
    uc_mem_region *region_cur = regions;
    printf("[Stalker][*] memory region begin:\n");
    while (count--) {
        printf("  [Stalker][*] memory region 0x%llx - 0x%llx (size=0x%llx), prot %d\n", region_cur->begin, region_cur->end, region_cur->end - region_cur->begin + 1, region_cur->perms);
        region_cur += 1;
    }
    printf("[Stalker][*] memory region end\n");
    free(regions);
}

std::shared_ptr<iblessing::MachOLoader> _defaultLoader = nullptr;

void print_backtrace(uc_engine *uc, shared_ptr<MachOLoader> loader) {
    if (!loader) {
        loader = _defaultLoader;
    }
    uint64_t pc, x29;
    assert(uc_reg_read(uc, UC_ARM64_REG_PC, &pc) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X29, &x29) == UC_ERR_OK);
    printf("[Stalker][*] Backtrace\n");
    int num = 1;

    while (true) {
        string symbolName = "?";
        string libraryName = "?";
        shared_ptr<MachOModule> module = loader->findModuleByAddr(pc);
        if (module) {
            libraryName = module->name;
            Symbol *sym = module->getSymbolByAddress(pc);
            if (sym && sym->name.length() > 0) {
                symbolName = sym->name;
            } else {
                Symbol *sym = module->getSymbolNearByAddress(pc);
                if (sym && sym->name.length() > 0) {
                    symbolName = sym->name + "?";
                }
            }
        }
        printf("#%d 0x%llx %s (in %s)\n", num, pc, symbolName.c_str(), libraryName.c_str());
        
        num += 1;
        // do backtrace
        uc_err err = uc_mem_read(uc, x29 + 8, &pc, sizeof(uint64_t));
        if (err != UC_ERR_OK) {
            break;
        }
        
        uint64_t fp = 0;
        err = uc_mem_read(uc, x29, &fp, sizeof(uint64_t));
        if (err != UC_ERR_OK) {
            break;
        }
        x29 = fp;
        
        if (pc == 0) {
            break;
        }
    }
}

void uc_debug_print_backtrace(uc_engine *uc) {
    BufferedLogger::globalLogger()->printBuffer();
    print_backtrace(uc);
}

void uc_debug_print_memory(uc_engine *uc, uint64_t addr, int format, int count) {
    printf("contents of 0x%llx:\n", addr);
    bool p64 = (format >= 8);
    for (int i = 0; i < count; i++) {
        if (i % 2 == 0) {
            if (i != 0) {
                printf("\n");
            }
            printf("0x%llx:", addr);
        }
        if (p64) {
            uint64_t val = 0;
            ensure_uc_mem_read(addr, &val, 8);
            printf(" 0x%llx", val);
            addr += 8;
        } else {
            uint32_t val = 0;
            ensure_uc_mem_read(addr, &val, 4);
            printf(" 0x%x", val);
            addr += 4;
        }
    }
    printf("\n");
}

void uc_debug_set_breakpoint(uc_engine *uc, uint64_t address) {
    breakpointMap[uc].insert(address);
}

bool uc_debug_check_breakpoint(uc_engine *uc, uint64_t address) {
    auto bps = breakpointMap[uc];
    if (bps.find(address) != bps.end()) {
        uc_debug_print_backtrace(uc);
        printf("[+][Stalker][Debugger] stop at breakpoint 0x%llx\n", address);
        pause();
        return true;
    }
    return false;
}
