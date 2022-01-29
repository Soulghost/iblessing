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
#include "macho-memory.hpp"
#include <map>

using namespace std;
using namespace iblessing;

static map<uc_engine *, map<uint64_t, string>> breakpointMap;
static int stopImmediatelyCount = 0;
static uint64_t stopImmediateAddress = 0;

#define debugLoopAssert_Msg(cond, msg) \
if (!(cond)) { \
    printf("debugger: %s\n iblessing debugger > ", msg); \
    continue; \
}

#define debugLoopAssert(cond) debugLoopAssert_Msg(cond, "invalid command")

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

void print_backtrace(uc_engine *uc, shared_ptr<MachOLoader> loader, bool beforePrologue) {
    if (!loader) {
        loader = _defaultLoader;
    }
    uint64_t pc, x29;
    assert(uc_reg_read(uc, UC_ARM64_REG_PC, &pc) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X29, &x29) == UC_ERR_OK);
    printf("[Stalker][*] Backtrace\n");
    int num = 1;
    
    vector<uint64_t> toPrint{pc};
    if (beforePrologue) {
        uint64_t lr;
        ensure_uc_reg_read(UC_ARM64_REG_LR, &lr);
        toPrint.push_back(lr);
    }
    int depth = 0;
    while (true) {
        if (depth++ > 20) {
            break;
        }
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

void uc_debug_print_backtrace(uc_engine *uc, bool beforePrologue) {
    BufferedLogger::globalLogger()->printBuffer();
    print_backtrace(uc, nullptr, beforePrologue);
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

void uc_debug_set_breakpoint(uc_engine *uc, uint64_t address, string desc) {
    breakpointMap[uc].insert({address, desc});
}

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
        } else {
            index = UC_ARM64_REG_INVALID;
        }
        *size = 4;
    } else {
        if (regName == "lr") {
            *size = 8;
            index = UC_ARM64_REG_LR;
        } else if (regName == "fp") {
            *size = 8;
            index = UC_ARM64_REG_FP;
        } else if (regName == "pc") {
            *size = 8;
            index = UC_ARM64_REG_PC;
        } else if (regName == "sp") {
            *size = 8;
            index = UC_ARM64_REG_SP;
        }
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
        debugLoopAssert(commandParts.size() > 0);
        string cmd = commandParts[0];
        if (cmd == "reg") {
            debugLoopAssert(commandParts.size() >= 3);
            string operation = commandParts[1];
            string regName = commandParts[2];
            size_t size = 0;
            uc_arm64_reg reg = uc_debug_regname2index(regName, &size);
            debugLoopAssert_Msg(reg != UC_ARM64_REG_INVALID, StringUtils::format("unknown reg name %s\n", regName.c_str()).c_str());
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
                debugLoopAssert_Msg(commandParts.size() == 4, "malformed input");
                if (size == 4) {
                    uint32_t val = (uint32_t)strtol(commandParts[3].c_str(), NULL, 16);
                    ensure_uc_reg_write(reg, &val);
                    printf("write 0x%x to reg %s\n", val, regName.c_str());
                } else if (size == 8) {
                    uint64_t val = strtol(commandParts[3].c_str(), NULL, 16);
                    ensure_uc_reg_write(reg, &val);
                    printf("write 0x%llx to reg %s\n", val, regName.c_str());
                }
            } else {
                debugLoopAssert_Msg(false, "unknown operation, please use <read> or <write>");
            }
        } else if (cmd == "bt") {
            uc_debug_print_backtrace(uc);
        } else if (cmd == "btt") {
            uc_debug_print_backtrace(uc, true);
        } else if (cmd == "mmap") {
            print_uc_mem_regions(uc);
        } else if (cmd == "frame") {
            uint64_t fp;
            ensure_uc_reg_read(UC_ARM64_REG_FP, &fp);
            uint64_t x29, x30;
            ensure_uc_mem_read(fp, &x29, sizeof(uint64_t));
            ensure_uc_mem_read(fp + 8, &x30, sizeof(uint64_t));
            printf("frame (0x%llx) info:\n\tbacked fp 0x%llx\n\tbacked lr 0x%llx\n", fp, x29, x30);
        } else if (cmd == "r64") {
            debugLoopAssert(commandParts.size() == 3);
            int format = 8;
            uint64_t addr = strtol(commandParts[1].c_str(), NULL, 16);
            uint64_t size = atol(commandParts[2].c_str());
            printf("debugger: read at 0x%llx, format %d, size %lld(0x%llx)\n", addr, format, size, size);
            debugLoopAssert_Msg(format == 8, "only support format = 8");
            if (format == 8) {
                uint64_t end = addr + size;
                uc_err err;
                while (addr < end) {
                    uint64_t a = 0xdeadbeef, b = 0xdeadbeef;
                    int errcnt = 0;
                    err = uc_mem_read(uc, addr, &a, format);
                    if (err != UC_ERR_OK) {
                        errcnt++;
                    }
                    addr += 8;
                    err = uc_mem_read(uc, addr, &b, format);
                    if (err != UC_ERR_OK) {
                        errcnt++;
                    }
                    addr += 8;
                    printf("0x%llx: 0x%llx 0x%llx\n", addr - 16, a, b);
                    if (errcnt > 0) {
                        printf("debugger: abort at 0x%llx, read failed count %d\n", addr - 16, errcnt);
                        break;
                    }
                }
            }
        } else if (cmd == "rs") {
            debugLoopAssert(commandParts.size() == 2);
            uint64_t addr = strtol(commandParts[1].c_str(), NULL, 16);
            char *str = MachoMemoryUtils::uc_read_string(uc, addr, 1000, true);
            printf("0x%llx: %s (%zu)\n", addr, str, strlen(str));
            free(str);
        } else if (cmd == "si") {
            if (commandParts.size() == 2) {
                int count = atoi(commandParts[1].c_str());
                stopImmediatelyCount = count;
            } else {
                stopImmediatelyCount = 1;
            }
            break;
        } else if (cmd == "skip") {
            uint64_t addr;
            ensure_uc_reg_read(UC_ARM64_REG_PC, &addr);
            addr += 4;
            stopImmediateAddress = addr;
            break;
        } else if (cmd == "b") {
            debugLoopAssert(commandParts.size() == 2);
            uint64_t addr = strtol(commandParts[1].c_str(), NULL, 16);
            breakpointMap[uc].insert({addr, ""});
            printf("debugger: set breakpoint at 0x%llx\n", addr);
        } else if (cmd == "bd") {
            debugLoopAssert(commandParts.size() == 2);
            uint64_t addr = strtol(commandParts[1].c_str(), NULL, 16);
            breakpointMap[uc].erase(addr);
            printf("debugger: delete breakpoint at 0x%llx\n", addr);
        } else if (cmd == "info") {
            uint64_t pc, lr, sp, fp;
            ensure_uc_reg_read(UC_ARM64_REG_PC, &pc);
            ensure_uc_reg_read(UC_ARM64_REG_FP, &fp);
            ensure_uc_reg_read(UC_ARM64_REG_LR, &lr);
            ensure_uc_reg_read(UC_ARM64_REG_SP, &sp);
            printf("debugger: thread state:\n");
            printf("pc 0x%llx, lr 0x%llx, sp 0x%llx, fp 0x%llx\n", pc, lr, sp, fp);
            for (int i = 0; i <= 28; i++) {
                uint64_t val;
                ensure_uc_reg_read(UC_ARM64_REG_X0 + i, &val);
                printf("x%d 0x%llx\n", i, val);
            }
        } else {
            debugLoopAssert(false);
        }
        
        printf("iblessing debugger > ");
    }
}

bool uc_debug_check_breakpoint(uc_engine *uc, uint64_t address) {
    auto bps = breakpointMap[uc];
    if (bps.find(address) != bps.end()) {
        uc_debug_print_backtrace(uc);
        string reason = bps[address].length() > 0 ? bps[address] : "default";
        printf("[+][Stalker][Debugger] stop at breakpoint 0x%llx, reason %s\n", address, reason.c_str());
        stopImmediatelyCount = 0;
        stopImmediateAddress = 0;
        debugLoop(uc);
        return true;
    }
    
    if (stopImmediatelyCount > 0) {
        if (--stopImmediatelyCount == 0) {
            BufferedLogger::globalLogger()->printBuffer();
            debugLoop(uc);
        }
        return true;
    } else if (stopImmediateAddress > 0) {
        stopImmediateAddress = 0;
        BufferedLogger::globalLogger()->printBuffer();
        debugLoop(uc);
        return true;
    }
    return false;
}

void uc_debug_breakhere(uc_engine *uc, string desc) {
    if (desc.length() > 0) {
        printf("[Stalker][+][Breakpoint] break for %s\n", desc.c_str());
    }
    debugLoop(uc);
}

string uc_get_thread_state_desc(uc_engine *uc) {
    string desc = "";
    uint64_t val;
    for (int i = 0; i < 29; i++) {
        uc_arm64_reg reg = (uc_arm64_reg)(UC_ARM64_REG_X0 + i);
        ensure_uc_reg_read(reg, &val);
        desc += StringUtils::format(", x%d 0x%llx", i, val);
    }
    return desc;
}
