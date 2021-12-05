//
//  uc_debugger_utils.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/10/5.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "uc_debugger_utils.hpp"
#include "buffered_logger.hpp"
#include "StringUtils.h"
#include "termcolor.h"
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
    uint64_t pc, x29, lr;
    assert(uc_reg_read(uc, UC_ARM64_REG_PC, &pc) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X29, &x29) == UC_ERR_OK);
    ensure_uc_reg_read(UC_ARM64_REG_LR, &lr);
    printf("[Stalker][*] Backtrace\n");
    int num = 1;
    
    vector<uint64_t> toPrint{pc, lr};
    while (true) {
        for (size_t i = 0; i < toPrint.size(); i++) {
            uint64_t pc = toPrint[i];
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
        }
        toPrint.clear();
        
        // do backtrace
        uc_err err = uc_mem_read(uc, x29 + 8, &pc, sizeof(uint64_t));
        if (err != UC_ERR_OK) {
            break;
        }
        toPrint.push_back(pc);
        
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

static void debugLoopAssert(uc_engine *uc, bool cond, string msg = "invalid command");

static uc_arm64_reg uc_debug_regname2index(string regName, size_t *size) {
    int index = UC_ARM64_REG_INVALID;
    char r = toupper(regName[0]);
    int num = atoi(regName.substr(1).c_str());
    if (r == 'X') {
        if (num <= 28) {
            index = UC_ARM64_REG_X0 + num;
        } else if (num <= 30) {
            index = UC_ARM64_REG_X29 + num - 29;
        } else {
            index = UC_ARM64_REG_INVALID;
        }
        *size = 8;
    } else if (r == 'W') {
        if (num >= 0 && num <= 30) {
            index = UC_ARM64_REG_W0 + num;
        } {
            index = UC_ARM64_REG_INVALID;
        }
        *size = 4;
    } else {
        if (regName == "lr") {
            *size = 8;
            return UC_ARM64_REG_LR;
        } else if (regName == "fp") {
            *size = 8;
            return UC_ARM64_REG_FP;
        } else if (regName == "pc") {
            *size = 8;
            return UC_ARM64_REG_PC;
        }
        return UC_ARM64_REG_INVALID;
    }
    return (uc_arm64_reg)index;
}

static void debugLoop(uc_engine *uc) {
    string line;
    printf("iblessing debugger > ");
    while (getline(std::cin, line)) {
        // FIXME: TODO: lldb command interpreter (CommandInterpreter)
        if (line == "c" || line == "continue") {
            break;
        }
        
        vector<string> commandParts = StringUtils::split(line, ' ');
        debugLoopAssert(uc, commandParts.size() > 0);
        string cmd = commandParts[0];
        if (cmd == "reg") {
            debugLoopAssert(uc, commandParts.size() >= 3);
            string operation = commandParts[1];
            string regName = commandParts[2];
            size_t size = 0;
            uc_arm64_reg reg = uc_debug_regname2index(regName, &size);
            debugLoopAssert(uc, reg != UC_ARM64_REG_INVALID, StringUtils::format("unknown reg name %s\n", regName.c_str()));
            if (operation == "read") {
                if (size == 4) {
                    int val;
                    ensure_uc_reg_read(reg, &val);
                    printf("%s: 0x%x\n", regName.c_str(), val);
                } else if (size == 8) {
                    uint64_t val;
                    ensure_uc_reg_read(reg, &val);
                    printf("%s: 0x%llx\n", regName.c_str(), val);
                }
            } else if (operation == "write") {
                debugLoopAssert(uc, false, "unsupport");
            } else {
                debugLoopAssert(uc, false, "unknown operation, please use <read> or <write>");
            }
        } else if (cmd == "bt") {
            uc_debug_print_backtrace(uc);
        } else if (cmd == "mmap") {
            print_uc_mem_regions(uc);
        } else if (cmd == "frame") {
            uint64_t fp;
            ensure_uc_reg_read(UC_ARM64_REG_FP, &fp);
            uint64_t x29, x30;
            ensure_uc_mem_read(fp, &x29, sizeof(uint64_t));
            ensure_uc_mem_read(fp + 8, &x30, sizeof(uint64_t));
            printf("frame (0x%llx) info:\n\tbacked fp 0x%llx\n\tbacked lr 0x%llx\n", fp, x29, x30);
        } else {
            debugLoopAssert(uc, false);
        }
        
        printf("iblessing debugger > ");
    }
}

static void debugLoopAssert(uc_engine *uc, bool cond, string msg) {
    if (cond) {
        return;
    }
    printf("debugger: %s\n", msg.c_str());
    debugLoop(uc);
}

bool uc_debug_check_breakpoint(uc_engine *uc, uint64_t address) {
    auto bps = breakpointMap[uc];
    if (bps.find(address) != bps.end()) {
        uc_debug_print_backtrace(uc);
        printf("[+][Stalker][Debugger] stop at breakpoint 0x%llx\n", address);
        debugLoop(uc);
        return true;
    }
    return false;
}

void uc_debug_breakhere(uc_engine *uc) {
    debugLoop(uc);
}
