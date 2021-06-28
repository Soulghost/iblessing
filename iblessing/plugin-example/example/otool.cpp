//
//  otool.cpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "otool.hpp"
#include "mach-universal.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include "ScannerContextManager.hpp"
#include "VirtualMemory.hpp"
#include "VirtualMemoryV2.hpp"
#include <iblessing-core/v2/util/StringUtils.h>
#include "SymbolTable.hpp"
#include "ObjcRuntime.hpp"
#include "DyldSimulator.hpp"
#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <iblessing-core/v2/objc/objc.hpp>
#include <iblessing-core/v2/dyld/dyld.hpp>

#define UnicornStackTopAddr      0x300000000

using namespace std;
using namespace iblessing;

int otool_main(int argc, const char **argv) {
    string filePath = "/Users/soulghost/Desktop/git/iblessing/iblessing/build/Debug-iphoneos/iblessing-sample.app/iblessing-sample";
//    string filePath = "/opt/one-btn/tmp/apps/WeChat/Payload/WeChat";
    
    shared_ptr<MachO> macho = MachO::createFromFile(filePath);
    assert(macho->loadSync() == IB_SUCCESS);
    ib_section_64 *textSect = macho->context->fileMemory->textSect;
    assert(textSect != nullptr);
    printf("[+] find __TEXT,__text at 0x%llx\n", textSect->addr);
    
    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);
    
    shared_ptr<Objc> objc = memory->objc;
    objc->loadClassList();
    objc->loadCategoryList();
    
    shared_ptr<Dyld> dyld = Dyld::create(macho, memory, objc);
    dyld->doBindAll();
    
    objc->realizeClasses([&](ObjcClassRuntimeInfo *info, uint64_t current, uint64_t total) {
#ifndef XcodeDebug
        fprintf(stdout, "\r\t[*] realize classes %lld/%lld (%.2f%%)", current, total, 100.0 * current / total);
        fflush(stdout);
#else
        if (current % 1000 == 0) {
            fprintf(stdout, "\r\t[*] realize classes %lld/%lld (%.2f%%)", current, total, 100.0 * current / total);
            fflush(stdout);
        }
#endif
    });
    
    // setup engine
    uc_engine *uc = memory->virtualMemory->getEngine();
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    
    shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    shared_ptr<SymbolTable> symtab = macho->context->symtab;
    shared_ptr<ObjcRuntime> rt = objc->getRuntime();
    
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
        
        uc_emu_start(uc, addr, addr + 4, 0, 1);
        uc_emu_stop(uc);
        
        Symbol *sym = symtab->getSymbolByAddress(addr);
        if (sym && sym->name.size() > 0) {
            printf("%s:\n", sym->name.c_str());
        }
        
        string comment;
        uint64_t resolvedAddress = 0;
        uint64_t branchAddress = 0;
        if (strcmp(last_mnemonic.c_str(), "adrp") == 0 &&
            strcmp(insn->mnemonic, "add") == 0) {
            if (UC_ERR_OK != uc_reg_read(uc, insn->detail->arm64.operands[1].reg, &resolvedAddress)) {
                resolvedAddress = 0;
            }
        }
        if (strcmp(last_mnemonic.c_str(), "adrp") == 0 &&
            strcmp(insn->mnemonic, "ldr") == 0) {
            if (UC_ERR_OK != uc_reg_read(uc, insn->detail->arm64.operands[0].reg, &resolvedAddress)) {
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
                    uc_reg_read(uc, UC_ARM64_REG_X0, &classAddr);
                    if (classAddr != 0) {
                        info = rt->getClassInfoByAddress(addr);
                    }
                    
                    char *sel = NULL;
                    uint64_t selAddr = 0;
                    uc_reg_read(uc, UC_ARM64_REG_X1, &selAddr);
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
