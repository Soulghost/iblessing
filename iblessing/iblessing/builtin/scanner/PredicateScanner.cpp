//
//  PredicateScanner.cpp
//  iblessing
//
//  Created by soulghost on 2020/4/27.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "PredicateScanner.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/core/dyld/DyldSimulator.hpp>
#include "ARM64Runtime.hpp"
#include "ARM64Disasembler.hpp"
#include "ARM64Runtime.hpp"
#include "ARM64ThreadState.hpp"
#include "VirtualMemory.hpp"
#include "VirtualMemoryV2.hpp"
#include "SymbolTable.hpp"
#include <iblessing-core/v2/util/StringUtils.h>
#include <set>

using namespace std;
using namespace iblessing;

int PredicateScanner::start() {
    cout << "[*] start NSPredicate Exploit Scanner" << endl;
    
    printf("  [*] Step 1. locate NSPredicate and NSString class refs\n");
    set<uint64_t> predicateAddrs;
    set<uint64_t> ocstringAddrs;
    VirtualMemory *vm = VirtualMemory::progressDefault();
    DyldSimulator::eachBind(vm->mappedFile, vm->segmentHeaders, vm->dyldinfo, [&](uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, uint64_t libraryOrdinal, const char *msg) {
        if (strcmp(symbolName, "_OBJC_CLASS_$_NSPredicate") == 0 ||
            strcmp(symbolName, "_OBJC_CLASS_$_NSString") == 0 ||
            strcmp(symbolName, "_OBJC_CLASS_$_NSMutableString") == 0) {
            uint64_t symbolAddr = addr + addend;
            if (predicateAddrs.find(symbolAddr) == predicateAddrs.end()) {
                printf("\t[+] find %s at 0x%llx\n", symbolName, symbolAddr);
                if (strcmp(symbolName, "_OBJC_CLASS_$_NSPredicate") == 0) {
                    predicateAddrs.insert(symbolAddr);
                } else {
                    ocstringAddrs.insert(symbolAddr);
                }
                
                // FIXME: trick write for external symbols
                vm->writeBySize(new uint64_t(symbolAddr), symbolAddr, 8, MemoryUnit::MemoryType::Common);
            }
        }
    });
    
    printf("  [*] Step 2. find __TEXT,__text\n");
    struct ib_section_64 *textSect = nullptr;
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
        cout << "\t" << termcolor::red << "[-] Error: cannot find __TEXT,__text section";
        cout << termcolor::reset << endl;
        return 1;
    }
    printf("\t[+] find __TEXT,__text at 0x%x\n", textSect->offset);
    
    printf("  [*] Step 3. scan in __text\n");
    
    set<uint64_t> predicate_refs;
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
                ARM64RegisterX *dst = dynamic_cast<ARM64RegisterX *>(state->getRegisterFromOprand(insn->detail->arm64.operands[0]));
                if (predicateAddrs.find(dst->getValue()) != predicateAddrs.end()) {
                    printf("\t[+] find NSPredicate ref at 0x%llx\n", insn->address);
                    predicate_refs.insert(insn->address);
                }
            }
        }
        if (strcmp(last_mnemonic.c_str(), "adrp") == 0 &&
            strcmp(insn->mnemonic, "ldr") == 0) {
            bool success = ARM64Runtime::handleLDR(insn, nullptr, nullptr, false, false);
            if (success) {
                ARM64RegisterX *dst = dynamic_cast<ARM64RegisterX *>(state->getRegisterFromOprand(insn->detail->arm64.operands[0]));
                if (dst != nullptr && dst->available && predicateAddrs.find(dst->getValue()) != predicateAddrs.end()) {
                    printf("\t[+] find NSPredicate ref at 0x%llx\n", insn->address);
                    predicate_refs.insert(insn->address);
                }
            }
        }
        last_mnemonic = insn->mnemonic;
#if 1
        float progress = 100.0 * (insn->address - startAddr) / addrRange;
        fprintf(stdout, "\r\t[*] %c 0x%llx/0x%llx (%.2f%%)", progressChars[progressCur], insn->address, endAddr, progress);
        fflush(stdout);
        progressCur = (++progressCur) % sizeof(progressChars);
#endif
    });
    delete disasm;
#endif
    
    printf("  [*] Step 4. symbolicate ref addresses\n");
    SymbolTable *symtab = SymbolTable::getInstance();
    for (uint64_t predicate_ref : predicate_refs) {
        Symbol *symbol = symtab->getSymbolNearByAddress(predicate_ref);
        if (symbol) {
            cout << "\t[+] find NSPredicate ref ";
            cout << termcolor::green << symbol->name << termcolor::reset;
            cout << StringUtils::format(" at 0x%llx\n", predicate_ref);
        } else {
            printf("\t[+] find NSPredicate ref at 0x%llx, ", predicate_ref);
            cout << termcolor::yellow << "cannot symbolicate it, maybe you should run restore-symbol first" << termcolor::reset;
            cout << endl;
        }
    }
    
    printf("  [*] Step 5. find sql injection exploits\n");
    bool findAttackSurface = false;
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    for (uint64_t predicate_ref : predicate_refs) {
        Symbol *symbol = symtab->getSymbolNearByAddress(predicate_ref);
        if (!symbol || !symbol->info) {
            continue;
        }
        ARM64Disassembler *disasm = new ARM64Disassembler();
        // search at predicate_ref +-
        uint64_t searchRange = 0x4 * 20;
        uint64_t lower = std::max(symbol->info->n_value, predicate_ref - searchRange);
        uint64_t upper = predicate_ref + searchRange;
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
            
            // FIXME: return by branch to objc_release, autorelease, etc.
            if (strcmp(insn->mnemonic, "ret") == 0) {
                *stop = true;
                return;
            }
            
            // skip predicate adrp & ldr or adrp & add
            if (insn->address == predicate_ref ||
                insn->address == predicate_ref - 0x4) {
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
                            if (strcmp("stringWithFormat:", maybeSEL) == 0) {
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
            Symbol *symbol = symtab->getSymbolNearByAddress(predicate_ref);
            if (symbol) {
                cout << "\t[+] NSPredicate ref ";
                cout << termcolor::green << symbol->name << termcolor::reset;
                cout << StringUtils::format(" at 0x%llx ", predicate_ref);
                cout << termcolor::yellow << "may have sql injection risks";
                cout << termcolor::reset << endl;
            } else {
                printf("\t[+] NSPredicate ref at 0x%llx, ", predicate_ref);
                cout << termcolor::yellow << "may have sql injection risks";
                cout << termcolor::reset << endl;
            }
        }
    }
    
    if (!findAttackSurface) {
        printf("\t[-] no attack surface found\n");
    }
    return 0;
}
