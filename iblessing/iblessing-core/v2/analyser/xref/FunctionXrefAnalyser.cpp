//
//  FunctionXrefAnalyser.cpp
//  iblessing
//
//  Created by Soulghost on 2021/5/3.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "FunctionXrefAnalyser.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/core/runtime/ARM64Runtime.hpp>

using namespace std;
using namespace iblessing;
using namespace iblessing::Analyser;

shared_ptr<FunctionXrefAnalyser> FunctionXrefAnalyser::create(shared_ptr<MachO> macho, shared_ptr<Memory> memory) {
    return make_shared<FunctionXrefAnalyser>(macho, memory);
}

ib_return_t FunctionXrefAnalyser::start() {
    assert(macho != nullptr && memory != nullptr);
    
    currentXREFs = {};
    xrefs = {};
    funcStartCursor = 0;
    progressCur = 0;
    
    shared_ptr<ScannerDisassemblyDriver> disasmDriver = this->disasmDriver;
    bool localDriver = false;
    if (!disasmDriver) {
        printf("\t[*] using local driver\n");
        disasmDriver = make_shared<ScannerDisassemblyDriver>();
        localDriver = true;
    }
    
    const char *prepadding = localDriver ? "" : "    ";
    
    cout << prepadding << "[*] start Symbol XREF Scanner" << endl;
        
    if (targetSymbols.size() == 0) {
        cout << termcolor::red;
        cout << StringUtils::format("%s[-] Error: you should specific symbols by -d 'symbols=<symbol>,<symbol>' or 'symbols=*'", prepadding);
        cout << termcolor::reset << endl;
        return 1;
    }
    
    set<string> symbols(targetSymbols.begin(), targetSymbols.end());
    
    printf("%s  [*] try to find xrefs for", prepadding);
    bool first = true;
    for (string symbol : symbols) {
        printf("%s%s", first ? "" : ", ", symbol.c_str());
        first = false;
    }
    printf("\n");
    
    printf("%s  [*] Step 1. find __TEXT,__text\n", prepadding);
    struct ib_section_64 *textSect = memory->fileMemory->textSect;
    printf("%s\t[+] find __TEXT,__text at 0x%llx\n", prepadding, textSect->addr);
    
    printf("%s  [*] Step 2. scan in __text\n", prepadding);
    uint64_t startAddr = textSect->addr;
    uint64_t endAddr = textSect->addr + textSect->size;
    uint64_t addrRange = endAddr - startAddr;
    uint8_t *codeData = memory->fileMemory->mappedFile + textSect->offset;
    printf("%s\t[*] start disassembler at 0x%llx\n", prepadding, startAddr);
    string last_mnemonic = "";
    char progressChars[] = {'\\', '|', '/', '-'};
    
#if 0
    uint64_t stub = 0x10038436C;
    codeData = codeData + stub - startAddr;
    startAddr = stub;
#endif
    
    funcStartCursor = startAddr;
    
    shared_ptr<SymbolTable> symtab = macho->context->symtab;
    disasmDriver->subscribeDisassemblyEvent(this, [=](bool success, cs_insn *insn, bool *stop, ARM64PCRedirect **redirect) {
#if 0
        if (!success) {
            cout << "\t[-]" << termcolor::yellow;
            cout << StringUtils::format(" an error occurred when disassemble at address 0x%llx", insn->address);
            cout << termcolor::reset << endl;
            return;
        }
#endif
        
        auto recordRET = [=]() {
            funcStartCursor = insn->address + 4;
            for (auto it = currentXREFs.begin(); it != currentXREFs.end(); it++) {
                for (SymbolXREF xref : it->second) {
                    xref.endAddr = insn->address;
                    xrefs[it->first].insert(xref);
                }
            }
//            xrefs.insert(currentXREFs.begin(), currentXREFs.end());
            currentXREFs.clear();
        };
        
        if (ARM64Runtime::isRET(symtab, insn) ||
            strcmp(insn->mnemonic, "brk") == 0) {
            recordRET();
            return;
        }
        
        bool isSymbolCall = false;
        bool isReturnCall = false;
        
        // call and return
        if (strcmp(insn->mnemonic, "b") == 0 ||
            strncmp(insn->mnemonic, "b.", 2) == 0) {
            isSymbolCall = true;
            // maybe return call
            isReturnCall = true;
        } else if (strcmp(insn->mnemonic, "bl") == 0 ||
                   strncmp(insn->mnemonic, "bl.", 3) == 0) {
            isSymbolCall = true;
        }
        
        if (isSymbolCall) {
            uint64_t pc = insn[0].detail->arm64.operands[0].imm;
            Symbol *symbol = symtab->getSymbolByAddress(pc);
            if (symbol && symbols.find(symbol->name) != symbols.end()) {
                if (insn->address > funcStartCursor) {
                    SymbolXREF xref = SymbolXREF();
                    xref.name = symbol->name;
                    xref.startAddr = funcStartCursor;
                    xref.callerAddr = insn->address;
                    xref.symbolAddr = pc;
                    currentXREFs[symbol->name].insert(xref);
                }
            } else {
                // no symbol address is not return
                isReturnCall = false;
            }
        }
        
        if (isReturnCall) {
            recordRET();
        }
        
        if (localDriver) {
#ifdef XcodeDebug
            static long _filter = 0;
            if (++_filter % 5000 == 0) {
#endif
            float progress = 100.0 * (insn->address - startAddr) / addrRange;
            fprintf(stdout, "\r\t[*] %c 0x%llx/0x%llx (%.2f%%)", progressChars[progressCur], insn->address, endAddr, progress);
            fflush(stdout);
            progressCur = (++progressCur) % sizeof(progressChars);
#ifdef XcodeDebug
            }
#endif
        }
        
        if (*stop) {
            uint64_t totalSize = 0;
            for (auto it = xrefs.begin(); it != xrefs.end(); it++) {
                totalSize += it->second.size();
            }
            
            cout << prepadding << "\t[*] A total of ";
            cout << termcolor::green << totalSize;
            cout << termcolor::reset;
            cout << " symbol xrefs were found" << endl;
            
            printf("%s[+] Symbol XREF Scanner Finished\n", prepadding);
        }
    });
    
    if (localDriver) {
        disasmDriver->startDisassembly(codeData, startAddr, endAddr);
    } else {
        printf("%s\t[*] Wating for driver event\n", prepadding);
    }
    
    return 0;
}
