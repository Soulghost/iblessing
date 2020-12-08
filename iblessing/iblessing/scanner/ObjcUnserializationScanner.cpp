//
//  ObjcUnserializationScanner.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcUnserializationScanner.hpp"
#include "termcolor.h"
#include "DyldSimulator.hpp"
#include "ARM64Runtime.hpp"
#include "ARM64Disasembler.hpp"
#include "ARM64Runtime.hpp"
#include "ARM64ThreadState.hpp"
#include "VirtualMemory.hpp"
#include "VirtualMemoryV2.hpp"
#include "SymbolTable.hpp"
#include "StringUtils.h"
#include <set>

using namespace std;
using namespace iblessing;

int ObjcUnserializationScanner::start() {
    cout << "[*] start Objc Unserialization Exploit Scanner" << endl;
    
    printf("  [*] Step 1. locate NSKeyedUnarchiver and UIPasteboard class refs\n");
    set<uint64_t> unarchiverAddrs;
    set<uint64_t> pasteboardAddrs;
    VirtualMemory *vm = VirtualMemory::progressDefault();
    DyldSimulator::eachBind(vm->mappedFile, vm->segmentHeaders, vm->dyldinfo, [&](uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, uint64_t libraryOrdinal, const char *msg) {
        if (strcmp(symbolName, "_OBJC_CLASS_$_NSKeyedUnarchiver") == 0 ||
            strcmp(symbolName, "_OBJC_CLASS_$_UIPasteboard") == 0) {
            uint64_t symbolAddr = addr + addend;
            if (unarchiverAddrs.find(symbolAddr) == unarchiverAddrs.end() ||
                pasteboardAddrs.find(symbolAddr) == pasteboardAddrs.end()) {
                printf("\t[+] find %s at 0x%llx\n", symbolName, symbolAddr);
                if (strcmp(symbolName, "_OBJC_CLASS_$_NSKeyedUnarchiver") == 0) {
                    unarchiverAddrs.insert(symbolAddr);
                } else {
                    pasteboardAddrs.insert(symbolAddr);
                }
                
                // FIXME: trick write for external symbols
                vm->writeBySize(new uint64_t(symbolAddr), symbolAddr, 8, MemoryUnit::MemoryType::Common);
            }
        }
    });
    
    printf("  [*] Step 2. find __TEXT,__text\n");
    struct ib_section_64 *textSect = nullptr;
    for (struct ib_segment_command_64 *seg : vm->segmentHeaders) {
        // FIX: https://github.com/Soulghost/iblessing/issues/5
//        if (strncmp(seg->segname, "__TEXT", 16) == 0) {
        struct ib_section_64 *sect = (struct ib_section_64 *)((uint8_t *)seg + sizeof(struct ib_segment_command_64));
        if (strncmp(sect->sectname, "__text", 16) == 0) {
            textSect = sect;
            break;
        }
//        }
    }
    if (!textSect) {
        cout << "\t" << termcolor::red << "[-] Error: cannot find __TEXT,__text section";
        cout << termcolor::reset << endl;
        return 1;
    }
    printf("\t[+] find __TEXT,__text at 0x%x\n", textSect->offset);
    
    printf("  [*] Step 3. scan in __text\n");
    
    set<uint64_t> unarchiverXrefs, pasteboardXrefs;
    ARM64ThreadState *state = ARM64ThreadState::mainThreadState();
#if 1
    ARM64Disassembler *disasm = new ARM64Disassembler();
    uint64_t startAddr = textSect->addr;
    uint64_t endAddr = textSect->addr + textSect->size;
    uint64_t addrRange = endAddr - startAddr;
    uint8_t *codeData = vm->mappedFile + textSect->offset;
    printf("\t[*] start disassembler at 0x%llx\n", startAddr);
    string last_mnemonic = "";
    char progressChars[] = {'\\', '|', '/', '-'};
    uint8_t progressCur = 0;
#if 0
    uint64_t stub = 0x103d65c1c;
    codeData = codeData + stub - startAddr;
    startAddr = stub;
#endif
    
    auto collector = [&](cs_insn *insn) {
        ARM64RegisterX *dst = dynamic_cast<ARM64RegisterX *>(state->getRegisterFromOprand(insn->detail->arm64.operands[0]));
        if (dst == nullptr || !dst->available) {
            return;
        }
        
        if (unarchiverAddrs.find(dst->getValue()) != unarchiverAddrs.end()) {
            printf("\t[+] find NSKeyedUnarchiver ref at 0x%llx\n", insn->address);
            unarchiverXrefs.insert(insn->address);
        } else if (pasteboardAddrs.find(dst->getValue()) != pasteboardAddrs.end()) {
            printf("\t[+] find UIPasteboard ref at 0x%llx\n", insn->address);
            pasteboardXrefs.insert(insn->address);
        }
    };
    
    disasm->startDisassembly(codeData, startAddr, [&](bool success, cs_insn *insn, bool *stop, ARM64PCRedirect **redirect) {
        if (insn->address >= endAddr) {
            printf("\t[*] reach to end of __text, stop\n");
            *stop = true;
            return;
        }
#if 0
        if (!success) {
            cout << "\t[-]" << termcolor::yellow;
            cout << StringUtils::format(" an error occurred when disassemble at address 0x%llx", insn->address);
            cout << termcolor::reset << endl;
            return;
        }
#endif
        if (strcmp(insn->mnemonic, "adrp") == 0) {
            ARM64Runtime::handleADRP(insn, nullptr, nullptr, false);
        }
        if (strcmp(last_mnemonic.c_str(), "adrp") == 0 &&
            strcmp(insn->mnemonic, "add") == 0) {
            bool success = ARM64Runtime::handleADD(insn, nullptr, nullptr, false);
            if (success) {
                collector(insn);
            }
        }
        if (strcmp(last_mnemonic.c_str(), "adrp") == 0 &&
            strcmp(insn->mnemonic, "ldr") == 0) {
            bool success = ARM64Runtime::handleLDR(insn, nullptr, nullptr, false, false);
            if (success) {
                collector(insn);
            }
        }
        last_mnemonic = insn->mnemonic;
#ifndef XcodeDebug
        float progress = 100.0 * (insn->address - startAddr) / addrRange;
        fprintf(stdout, "\r\t[*] %c 0x%llx/0x%llx (%.2f%%)", progressChars[progressCur], insn->address, endAddr, progress);
        fflush(stdout);
        progressCur = (++progressCur) % sizeof(progressChars);
#else
        float progress = 100.0 * (insn->address - startAddr) / addrRange;
        if (startAddr % 10000 == 0) {
            fprintf(stdout, "\r\t[*] %c 0x%llx/0x%llx (%.2f%%)", progressChars[progressCur], insn->address, endAddr, progress);
            fflush(stdout);
        }
        progressCur = (++progressCur) % sizeof(progressChars);
#endif
    });
    delete disasm;
#endif
    
    printf("  [*] Step 4. symbolicate ref addresses\n");
    SymbolTable *symtab = SymbolTable::getInstance();

    auto xrefPrinter = [&](const char *className, set<uint64_t> xrefs) {
        for (uint64_t xref : xrefs) {
            Symbol *symbol = symtab->getSymbolNearByAddress(xref);
            if (symbol) {
                cout << "\t[+] find " << className << " ref ";
                cout << termcolor::green << symbol->name << termcolor::reset;
                cout << StringUtils::format(" at 0x%llx\n", xref);
            } else {
                printf("\t[+] find %s ref at 0x%llx, ", className, xref);
                cout << termcolor::yellow << "cannot symbolicate it, maybe you should run restore-symbol first" << termcolor::reset;
                cout << endl;
            }
        }
    };
    
    xrefPrinter("NSKeyedUnarchiver", unarchiverXrefs);
    xrefPrinter("UIPasteboard", pasteboardXrefs);
    
    printf("  [*] Step 5. find insecure unarchive exploits\n");
    bool findAttackSurface = false;
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    for (uint64_t xref : unarchiverXrefs) {
        Symbol *symbol = symtab->getSymbolNearByAddress(xref);
        if (!symbol || !symbol->info) {
            continue;
        }
        ARM64Disassembler *disasm = new ARM64Disassembler();
        // search at predicate_ref +-
        uint64_t searchRange = sizeof(uint32_t) * 30;
        uint64_t symbolAddr = symbol->info->n_value;
        uint64_t lower = std::max(symbolAddr, xref - searchRange);
        uint64_t upper = xref + searchRange;
        uint8_t *codeData = vm->mappedFile + lower - vm->vmaddr_base;
        std::string last_mnemonic = "";
        bool inDanger = false;
        disasm->startDisassembly(codeData, lower, [&](bool success, cs_insn *insn, bool *stop, ARM64PCRedirect **redirect) {
            if (insn->address > upper) {
                *stop = true;
                return;
            }
            
            if (!success) {
                return;
            }
            
            // detect return
            if (ARM64Runtime::isRET(insn)) {
                *stop = true;
                return;
            }
            
            // skip predicate adrp & ldr or adrp & add
            if (insn->address == xref ||
                insn->address == xref - 0x4) {
                return;
            }
            
            if (strcmp(insn->mnemonic, "adrp") == 0) {
                ARM64Runtime::handleADRP(insn, nullptr, nullptr, false);
            }
            
            if (strcmp(last_mnemonic.c_str(), "adrp") == 0 &&
                strcmp(insn->mnemonic, "add") == 0) {
                bool success = ARM64Runtime::handleADD(insn, nullptr, nullptr, false);
                if (success) {
                    ARM64RegisterX *dst = dynamic_cast<ARM64RegisterX *>(state->getRegisterFromOprand(insn->detail->arm64.operands[0]));
                    if (dst && dst->available) {
                        // FIXME: maybe some routine here
                    }
                }
            }
            if (strcmp(insn->mnemonic, "ldr") == 0) {
                bool success = ARM64Runtime::handleLDR(insn, nullptr, nullptr, false, false);
                if (success) {
                    ARM64RegisterX *dst = dynamic_cast<ARM64RegisterX *>(state->getRegisterFromOprand(insn->detail->arm64.operands[0]));
                    if (dst && dst->available) {
                        char *maybeSEL = vm2->readString(dst->getValue(), 1000);
                        if (maybeSEL) {
                            if (strcmp("unarchiveObjectWithData:", maybeSEL) == 0 ||
                                strcmp("unarchiveTopLevelObjectWithData:error:", maybeSEL) == 0 ||
                                strcmp("unarchiveObjectWithFile:", maybeSEL) == 0) {
                                *stop = true;
                                inDanger = true;
                                return;
                            }
                        }
                    }
                }
            }
            last_mnemonic = insn->mnemonic;
        });
        delete disasm;
        
        if (inDanger) {
            findAttackSurface = true;
            Symbol *symbol = symtab->getSymbolNearByAddress(xref);
            if (symbol) {
                cout << "\t[+] NSKeyedUnarchiver ref ";
                cout << termcolor::green << symbol->name << termcolor::reset;
                cout << StringUtils::format(" at 0x%llx ", xref);
                cout << termcolor::yellow << "may have insecure unserialization risks";
                cout << termcolor::reset << endl;
            } else {
                printf("\t[+] NSKeyedUnarchiver ref at 0x%llx, ", xref);
                cout << termcolor::yellow << "may have insecure unserialization risks";
                cout << termcolor::reset << endl;
            }
        }
    }
    
    if (!findAttackSurface) {
        printf("\t[-] no attack surface found\n");
    }
    return 0;
}

