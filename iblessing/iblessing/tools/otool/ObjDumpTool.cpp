//
//  ObjDumpTool.cpp
//  iblessing
//
//  Created by soulghost on 2021/1/16.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "ObjDumpTool.hpp"
#include "mach-universal.hpp"
#include "termcolor.h"
#include "ScannerContextManager.hpp"
#include "VirtualMemory.hpp"
#include "VirtualMemoryV2.hpp"
#include "StringUtils.h"
#include "SymbolTable.hpp"
#include "ObjcRuntime.hpp"
#include "DyldSimulator.hpp"
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#define UnicornStackTopAddr      0x300000000

using namespace std;
using namespace iblessing;

//static uc_hook insn_hook, memexp_hook;

static cs_insn* copy_insn(cs_insn *insn) {
    cs_insn *buffer = (cs_insn *)malloc(sizeof(cs_insn));
    memcpy(buffer, insn, sizeof(cs_insn));
    buffer->detail = (cs_detail *)malloc(sizeof(cs_detail));
    memcpy(buffer->detail, insn->detail, sizeof(cs_detail));
    return buffer;
}

static void free_insn(cs_insn *insn) {
    free(insn->detail);
    free(insn);
}

class EngineContext {
public:
    int identifer;
    uc_engine *engine;
    uc_context *defaultContext;
};

static map<uc_engine *, EngineContext *> engineContexts;

static uc_engine* createEngine(int identifier) {
    uc_engine *uc;
    uc_context *ctx;
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("\t[-] error: %s\n", uc_strerror(err));
        return NULL;
    }
    
    VirtualMemoryV2::progressDefault()->mappingMachOToEngine(uc, nullptr);
    
    // setup default thread state
    assert(uc_context_alloc(uc, &ctx) == UC_ERR_OK);
    
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    uc_context_save(uc, ctx);
    
    // build context
    EngineContext *engineCtx = new EngineContext();
    engineCtx->identifer = identifier;
    engineCtx->engine = uc;
    engineCtx->defaultContext = ctx;
    engineContexts[uc] = engineCtx;
    return uc;
}

int ObjDumpTool::dumpTextSection(string filePath) {
    shared_ptr<ScannerContext> ctx = make_shared<ScannerContext>();
    scanner_err err = ctx->setupWithBinaryPath(filePath);
    if (err != SC_ERR_OK) {
        switch (err) {
            case SC_ERR_INVALID_BINARY:
                cout << termcolor::red << "[-] ScannerContextManager Error: invalid binary file " << filePath;
                cout << termcolor::reset << endl;
                return 1;
            case SC_ERR_MAP_FAILED:
                cout << termcolor::red << "[-] ScannerContextManager Error: mmap failed, please try again";
                cout << termcolor::reset << endl;
                return 1;
            case SC_ERR_UNSUPPORT_ARCH:
                cout << termcolor::red << "[-] ScannerContextManager Error: unsupport arch, only support aarch64 now";
                cout << termcolor::reset << endl;
                return 1;
            case SC_ERR_MACHO_MISSING_SEGMENT_DYLD:
                cout << termcolor::red << "[-] ScannerContextManager Error: DYLD_INFO_ONLY segment not found, maybe the mach-o file is corrupted";
                cout << termcolor::reset << endl;
                return 1;
            case SC_ERR_MACHO_MISSING_SEGMENT_TEXT:
                cout << termcolor::red << "[-] ScannerContextManager Error: __TEXT segment not found, maybe the mach-o file is corrupted";
                cout << termcolor::reset << endl;
                return 1;
            case SC_ERR_MACHO_MISSING_SEGMENT_SYMTAB:
                cout << termcolor::red << "[-] ScannerContextManager Error: SYMTAB segment not found, maybe the mach-o file is corrupted";
                cout << endl;
                return 1;
            case SC_ERR_MACHO_MISSING_SEGMENT_DYSYMTAB:
                cout << termcolor::red << "[-] ScannerContextManager Error: DYSYMTAB segment not found, maybe the mach-o file is corrupted";
                cout << endl;
                return 1;
            default:
                cout << termcolor::red << "[-] ScannerContextManager Error: ?";
                return 1;
        }
    }
    
    struct ib_section_64 *textSect = nullptr;
    VirtualMemory *vm = VirtualMemory::progressDefault();
    for (struct ib_segment_command_64 *seg : vm->segmentHeaders) {
        if (strncmp(seg->segname, "__TEXT", 16) == 0) {
            struct ib_section_64 *sect = (struct ib_section_64 *)((uint8_t *)seg + sizeof(struct ib_segment_command_64));
            if (strncmp(sect->sectname, "__text", 16) == 0) {
                textSect = sect;
                break;
            }
        }
    }
    if (!textSect) {
        for (struct ib_segment_command_64 *seg : vm->segmentHeaders) {
            struct ib_section_64 *sect = (struct ib_section_64 *)((uint8_t *)seg + sizeof(struct ib_segment_command_64));
            if (strncmp(sect->sectname, "__text", 16) == 0) {
                textSect = sect;
                break;
            }
        }
        cout << termcolor::yellow << "[-] Warn: __TEXT,__text not found, try ?,__text";
        cout << termcolor::reset << endl;
        if (!textSect) {
            cout << "\t" << termcolor::red << "[-] Error: cannot find __TEXT,__text section";
            cout << termcolor::reset << endl;
            return 1;
        }
    }
    printf("[+] find __TEXT,__text at 0x%llx\n", textSect->addr);
    
    // class realize
    printf("[*] Realize all app classes\n");
    ObjcRuntime *rt = ObjcRuntime::getInstance();
    SymbolTable *symtab = SymbolTable::getInstance();
    unordered_map<string, uint64_t> &classList = rt->classList;
    uint64_t count = 0, total = classList.size();
    vector<ObjcMethod *> methods;
    set<uint64_t> impAddrs;
    for (auto it = classList.begin(); it != classList.end(); it++) {
        if (it->second == 0) {
            printf("\t[+] skip bad class %s\n", it->first.c_str());
        }
        ObjcClassRuntimeInfo *classInfo = rt->getClassInfoByAddress(it->second);
        Vector<ObjcMethod *> allMethods = classInfo->getAllMethods();
        methods.insert(methods.end(), allMethods.begin(), allMethods.end());
        for (ObjcMethod *m : allMethods) {
            impAddrs.insert(m->imp);
        }
        count++;
#ifndef XcodeDebug
        fprintf(stdout, "\r\t[*] realize classes %lld/%lld (%.2f%%)", count, total, 100.0 * count / total);
        fflush(stdout);
#else
        if (count % 1000 == 0) {
            fprintf(stdout, "\r\t[*] realize classes %lld/%lld (%.2f%%)", count, total, 100.0 * count / total);
            fflush(stdout);
        }
#endif
    }
    
    // each bind
    // create engine
    uc_engine *engine = createEngine(0);
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    DyldSimulator::eachBind(vm2->getMappedFile(), vm2->getSegmentHeaders(), vm2->getDyldInfo(), [&](uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, uint64_t libraryOrdinal, const char *msg) {
        uint64_t symbolAddr = addr + addend;
        
        // load non-lazy symbols
        uc_mem_write(engine, symbolAddr, &symbolAddr, 8);
        vm2->write64(symbolAddr, symbolAddr);
        
        // record class info
        if (string(symbolName).rfind("_OBJC_CLASS_$") == 0) {
            string className;
            vector<string> parts = StringUtils::split(symbolName, '_');
            if (parts.size() > 1) {
                className = parts[parts.size() - 1];
            } else {
                className = symbolName;
            }
            
            ObjcClassRuntimeInfo *externalClassInfo = rt->getClassInfoByName(className);
            if (!externalClassInfo) {
                externalClassInfo = new ObjcClassRuntimeInfo();
                externalClassInfo->className = className;
                externalClassInfo->isExternal = true;
                externalClassInfo->address = symbolAddr;
                rt->name2ExternalClassRuntimeInfo[externalClassInfo->className] = externalClassInfo;
                rt->runtimeInfo2address[externalClassInfo] = symbolAddr;
            }
            rt->externalClassRuntimeInfo[symbolAddr] = externalClassInfo;
            
        } else if (strcmp(symbolName, "__NSConcreteGlobalBlock") == 0 ||
                   strcmp(symbolName, "__NSConcreteStackBlock") == 0) {
            rt->blockISAs.insert(symbolAddr);
        }
        
        // record symbol
        Symbol *sym = new Symbol();
        sym->name = symbolName;
        struct ib_nlist_64 *nl = (struct ib_nlist_64 *)calloc(1, sizeof(ib_nlist_64));
        nl->n_value = symbolAddr;
        sym->info = nl;
        symtab->insertSymbol(sym);
    });
    
    // dis all
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    // setup unicorn virtual memory
    uint64_t addr = textSect->addr;
    uint64_t end = textSect->addr + textSect->size;
    string last_mnemonic;
    while (addr < end) {
        bool success;
        uint32_t code = vm2->read32(addr, &success);
        if (!success) {
            cout << termcolor::yellow << "[-] Warn: Failed to read data from";
            cout << StringUtils::format(" 0x%llx", addr);
            cout << termcolor::reset << endl;
            last_mnemonic = "";
            addr += 4;
            continue;
        }
        
        cs_insn *insn = nullptr;
        size_t count = cs_disasm(handle, (uint8_t *)&code, 4, addr, 0, &insn);
        if (count != 1) {
            cout << termcolor::yellow << "[-] Warn: Failed to disassemble from";
            cout << StringUtils::format(" 0x%llx", addr);
            cout << termcolor::reset << endl;
            addr += 4;
            last_mnemonic = "";
            continue;
        }
        
        uc_emu_start(engine, addr, addr + 4, 0, 1);
        uc_emu_stop(engine);
        
        Symbol *sym = symtab->getSymbolByAddress(addr);
        if (sym && sym->name.size() > 0) {
            printf("%s:\n", sym->name.c_str());
        }
        
        string comment;
        uint64_t resolvedAddress = 0;
        uint64_t branchAddress = 0;
        if (strcmp(last_mnemonic.c_str(), "adrp") == 0 &&
            strcmp(insn->mnemonic, "add") == 0) {
            if (UC_ERR_OK != uc_reg_read(engine, insn->detail->arm64.operands[1].reg, &resolvedAddress)) {
                resolvedAddress = 0;
            }
        }
        if (strcmp(last_mnemonic.c_str(), "adrp") == 0 &&
            strcmp(insn->mnemonic, "ldr") == 0) {
            if (UC_ERR_OK != uc_reg_read(engine, insn->detail->arm64.operands[0].reg, &resolvedAddress)) {
                resolvedAddress = 0;
            }
        }
        if (strcmp(insn->mnemonic, "b") == 0 ||
            strcmp(insn->mnemonic, "bl") == 0 ||
            strncmp(insn->mnemonic, "b.", 2) == 0 ||
            strncmp(insn->mnemonic, "bl.", 2) == 0 ||
            strcmp(insn->mnemonic, "cbz") == 0 ||
            strcmp(insn->mnemonic, "cbnz") == 0) {
            branchAddress = insn->detail->arm64.operands[0].imm;
        }
        
        if (resolvedAddress > 0) {
            pair<string, string> segInfo = vm2->querySegInfo(resolvedAddress);
            if (segInfo.second == "__objc_selrefs") {
                bool success;
                uint64_t selAddr = vm2->read64(resolvedAddress, &success);
                if (success) {
                    char *sel = vm2->readString(selAddr, 1000);
                    if (sel) {
                        comment = "Objc selector ref: " + string(sel);
                        free(sel);
                    }
                }
            } else if (segInfo.second == "__objc_methname") {
                char *sel = vm2->readString(resolvedAddress, 1000);
                if (sel) {
                    comment = "Objc selector ref: " + string(sel);
                    free(sel);
                }
            } else if (segInfo.second == "__cfstring") {
                char *content = vm2->readAsCFStringContent(resolvedAddress);
                if (content) {
                    comment = StringUtils::format("Objc cfstring ref: @\"%s\"", content);
                    free(content);
                }
            } else if (segInfo.second == "__objc_classrefs") {
                uint64_t classAddr = vm2->read64(resolvedAddress, NULL);
                Symbol *sym = symtab->getSymbolByAddress(classAddr);
                if (sym) {
                    comment = "Objc class ref: " + sym->name;
                }
            }
        }
        
        if (branchAddress > 0) {
            Symbol *sym = symtab->getSymbolByAddress(branchAddress);
            if (sym) {
                if (strncmp(sym->name.c_str(), "_objc_msgSend", strlen("_objc_msgSend")) == 0) {
                    ObjcClassRuntimeInfo *info = nullptr;
                    uint64_t classAddr = 0;
                    uc_reg_read(engine, UC_ARM64_REG_X0, &classAddr);
                    if (classAddr != 0) {
                        info = rt->getClassInfoByAddress(addr);
                    }
                    
                    char *sel = NULL;
                    uint64_t selAddr = 0;
                    uc_reg_read(engine, UC_ARM64_REG_X1, &selAddr);
                    if (selAddr != 0) {
                        sel = vm2->readString(selAddr, 1000);
                    }
                    
                    comment = "Objc message: ";
                    string prefix, classExpr, selExpr;
                    if (info && sel) {
                        ObjcMethod *method = rt->inferNearestMethod("?", info->className, string(sel));
                        if (method) {
                            prefix = method->isClassMethod ? "+" : "-";
                        } else {
                            prefix = "?";
                        }
                    } else {
                        prefix = "?";
                    }
                    
                    bool superCall = false;
                    if (strncmp(sym->name.c_str(), "_objc_msgSendSuper", strlen("_objc_msgSendSuper")) == 0) {
                        superCall = true;
                    }
                    
                    if (info) {
                        if (superCall) {
                            classExpr = StringUtils::format("[%s super]", info->className.c_str());
                        } else {
                            classExpr = info->className;
                        }
                    } else {
                        string expr;
                        Symbol *sym = symtab->getSymbolByAddress(classAddr);
                        if (sym) {
                            prefix = "+";
                            if (sym->name.rfind("_OBJC_") != -1 &&
                                sym->name.rfind("_$_") != -1) {
                                expr = StringUtils::split(sym->name, '$')[1].substr(1);
                            } else {
                                expr = sym->name;
                            }
                        } else {
                            expr = "x0";
                        }
                        if (superCall) {
                            classExpr = "[" + expr + " super]";
                        } else {
                            classExpr = expr;
                        }
                    }
                    
                    if (sel) {
                        selExpr = StringUtils::format("%s", sel);
                    } else {
                        selExpr = "?";
                    }
                    
                    if (sel) {
                        free(sel);
                    }
                    
                    comment += StringUtils::format("%s[%s %s]", prefix.c_str(), classExpr.c_str(), selExpr.c_str());
                } else {
                    if (sym->isStub) {
                        comment = StringUtils::format("symbol stub for: %s", sym->name.c_str());
                    } else {
                        comment = StringUtils::format("%s %s", insn->mnemonic, sym->name.c_str());
                    }
                }
            }
        }
        
        printf("%016llx      %-8s %s", insn->address, insn->mnemonic, insn->op_str);
        if (comment.length() > 0) {
            printf(" ; %s\n", comment.c_str());
        } else {
            printf("\n");
        }
        last_mnemonic = insn->mnemonic;
        addr += 4;
    }
    return 0;
}
