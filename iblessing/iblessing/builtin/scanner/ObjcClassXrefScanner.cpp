//
//  ObjcClassXrefScanner.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcClassXrefScanner.hpp"
#include "ARM64Runtime.hpp"
#include "ARM64Disasembler.hpp"
#include "ARM64Runtime.hpp"
#include "ARM64ThreadState.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/scanner/dispatcher/ScannerDispatcher.hpp>
#include <iblessing-core/v2/analyser/wrapper/SimpleWrapperAnalyser.hpp>
#include <iblessing/builtin/serialization/SymbolWrapperSerializationManager.hpp>
#include <set>

using namespace std;
using namespace iblessing;

//__attribute__((constructor))
//static void scannerRegister() {
//    ScannerDispatcher::getInstance()->registerScanner("symbol-wrapper", []() {
//        return new ObjcClassXrefScanner("objc-class-xref", "scan for class xrefs");
//    });
//};

int ObjcClassXrefScanner::start() {
    assert(macho != nullptr);
    cout << "[*] start Objc Class Xref Scanner" << endl;
    if (options.find("classes") == options.end()) {
        cout << termcolor::red;
        cout << StringUtils::format("Error: you should specific class by -d 'classes=<class>,<class>'");
        cout << termcolor::reset << endl;
        return 1;
    }
    
    string classesExpr = options["classes"];
    vector<string> classes = StringUtils::split(classesExpr, ',');
    map<string, pair<set<uint64_t>, set<uint64_t>>> classRecords;
    for (string clazz : classes) {
        string classSymbol = StringUtils::format("_OBJC_CLASS_$_%s", clazz.c_str());
        classRecords[classSymbol] = {};
        
        uint64_t address = ObjcRuntime::getInstance()->getClassAddrByName(classSymbol);
        if (address > 0) {
            classRecords[classSymbol].first.insert(address);
        }
    }
    
    printf("  [*] try to find ");
    bool first = true;
    for (auto it = classRecords.begin(); it != classRecords.end(); it++) {
        printf("%s%s", first ? "" : ", ",  it->first.c_str());
        first = false;
    }
    printf("\n");
    
    printf("  [*] Step 1. locate class refs\n");
    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);
    this->memory = memory;
    shared_ptr<VirtualMemory> vm = memory->fileMemory;
    DyldSimulator::eachBind(vm->mappedFile, vm->segmentHeaders, vm->dyldinfo, [&](uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, uint64_t libraryOrdinal, const char *msg) {
        if (classRecords.find((symbolName)) != classRecords.end()) {
            uint64_t symbolAddr = addr + addend;
            pair<set<uint64_t>, set<uint64_t>> &record = classRecords[symbolName];
            if (record.first.find(symbolAddr) == record.first.end()) {
                record.first.insert(symbolAddr);
                
                // FIXME: trick write for external symbols
                vm->writeBySize(new uint64_t(symbolAddr), symbolAddr, 8, MemoryUnit::MemoryType::Common);
            }
        }
    });
    for (auto it = classRecords.begin(); it != classRecords.end(); it++) {
        for (uint64_t addr : it->second.first) {
            printf("\t[+] find %s at 0x%llx\n", it->first.c_str(), addr);
        }
    }
    
    printf("  [*] Step 2. find __TEXT,__text\n");
    struct ib_section_64 *textSect = vm->textSect;
    printf("\t[+] find __TEXT,__text at 0x%x\n", textSect->offset);
    
    printf("  [*] Step 3. scan in __text\n");
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
        
        if (!success) {
#if 0
            cout << "\t[-]" << termcolor::yellow;
            cout << StringUtils::format(" an error occurred when disassemble at address 0x%llx", insn->address);
            cout << termcolor::reset << endl;
#endif
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
                if (dst == nullptr || !dst->available) {
                    return;
                }
                uint64_t targetAddr = dst->getValue();
                for (auto it = classRecords.begin(); it != classRecords.end(); it++) {
                    if (it->second.first.find(targetAddr) != it->second.first.end()) {
                        printf("\t[+] find %s ref at 0x%llx\n", it->first.c_str(), insn->address);
                        it->second.second.insert(insn->address);
                    }
                }
//                if (classAddrs.find() != classAddrs.end()) {
//                    printf("\t[+] find %s ref at 0x%llx\n", classSymbol.c_str(), insn->address);
//                    classXRefs.insert(insn->address);
//                }
            }
        }
        if (strcmp(last_mnemonic.c_str(), "adrp") == 0 &&
            strcmp(insn->mnemonic, "ldr") == 0) {
            bool success = ARM64Runtime::handleLDR(insn, nullptr, nullptr, false, false);
            if (success) {
                ARM64RegisterX *dst = dynamic_cast<ARM64RegisterX *>(state->getRegisterFromOprand(insn->detail->arm64.operands[0]));
                if (dst && dst->available) {
                    uint64_t targetAddr = dst->getValue();
                    for (auto it = classRecords.begin(); it != classRecords.end(); it++) {
                        if (it->second.first.find(targetAddr) != it->second.first.end()) {
                            printf("\t[+] find %s ref at 0x%llx\n", it->first.c_str(), insn->address);
                            it->second.second.insert(insn->address);
                        }
                    }
                }
//                if (dst != nullptr && dst->available && classAddrs.find(dst->getValue()) != classAddrs.end()) {
//                    printf("\t[+] find %s ref at 0x%llx\n", classSymbol.c_str(), insn->address);
//                    classXRefs.insert(insn->address);
//                }
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
    shared_ptr<SymbolTable> symtab = macho->context->symtab;
    for (auto it = classRecords.begin(); it != classRecords.end(); it++) {
        string classSymbol = it->first;
        printf("    [+] %s -|\n", classSymbol.c_str());
        set<uint64_t> xrefs = it->second.second;
        for (uint64_t xref : xrefs) {
            Symbol *symbol = symtab->getSymbolNearByAddress(xref);
            if (symbol) {
                cout << "\t[+] find " << classSymbol << " ref ";
                cout << termcolor::green << symbol->name << termcolor::reset;
                cout << StringUtils::format(" at 0x%llx\n", xref);
            } else {
                printf("\t[+] find %s ref at 0x%llx, ", classSymbol.c_str(), xref);
                cout << termcolor::yellow << "cannot symbolicate it, maybe you should run restore-symbol first" << termcolor::reset;
                cout << endl;
            }
        }
    }
    return 0;
}
