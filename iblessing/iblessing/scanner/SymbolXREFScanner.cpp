//
//  SymbolXREFScanner.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/2.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "SymbolXREFScanner.hpp"
#include "termcolor.h"
#include "StringUtils.h"
#include "VirtualMemory.hpp"
#include "ARM64Runtime.hpp"
#include "ARM64Disasembler.hpp"
#include "SymbolTable.hpp"
#include <set>

using namespace std;
using namespace iblessing;

int SymbolXREFScanner::start() {
    ScannerDisassemblyDriver *disasmDriver = this->driver;
    bool localDriver = false;
    if (!disasmDriver) {
        printf("\t[*] using local driver\n");
        disasmDriver = new ScannerDisassemblyDriver();
        localDriver = true;
    }
    
    const char *prepadding = localDriver ? "" : "    ";
    
    cout << prepadding << "[*] start Symbol XREF Scanner" << endl;
        
    if (options.find("symbols") == options.end()) {
        cout << termcolor::red;
        cout << StringUtils::format("%s[-] Error: you should specific symbols by -d 'symbols=<symbol>,<symbol>' or 'symbols=*'", prepadding);
        cout << termcolor::reset << endl;
        return 1;
    }
    
    string symbolsExpr = options["symbols"];
    vector<string> allSymbols = StringUtils::split(symbolsExpr, ',');
    set<string> symbols(allSymbols.begin(), allSymbols.end());
    
    // setup recordPath
    string recordPath = StringUtils::path_join(outputPath, fileName + "_symbol-xrefs.iblessing.txt");
    
    printf("%s  [*] try to find xrefs for", prepadding);
    bool first = true;
    for (string symbol : symbols) {
        printf("%s%s", first ? "" : ", ", symbol.c_str());
        first = false;
    }
    printf("\n");
    
    printf("%s  [*] Step1. find __TEXT,__text\n", prepadding);
    VirtualMemory *vm = VirtualMemory::progressDefault();
    struct section_64 *textSect = vm->textSect;
    printf("%s\t[+] find __TEXT,__text at 0x%llx\n", prepadding, textSect->addr);
    
    printf("%s  [*] Step 2. scan in __text\n", prepadding);
    
    
    uint64_t startAddr = textSect->addr;
    uint64_t endAddr = textSect->addr + textSect->size;
    uint64_t addrRange = endAddr - startAddr;
    uint8_t *codeData = vm->mappedFile + textSect->offset;
    printf("%s\t[*] start disassembler at 0x%llx\n", prepadding, startAddr);
    string last_mnemonic = "";
    char progressChars[] = {'\\', '|', '/', '-'};
    
#if 0
    uint64_t stub = 0x10038436C;
    codeData = codeData + stub - startAddr;
    startAddr = stub;
#endif
    
    funcStartCursor = startAddr;
    disasmDriver->subscribeDisassemblyEvent(this, [=](bool success, cs_insn *insn, bool *stop, ARM64PCRedirect **redirect) {
        SymbolTable *symtab = SymbolTable::getInstance();
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
            xrefs.insert(currentXREFs.begin(), currentXREFs.end());
            currentXREFs.clear();
        };
        
        if (ARM64Runtime::isRET(insn) ||
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
                    xref.xrefAddrs.insert(pc);
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
        delete disasmDriver;
    } else {
        printf("%s\t[*] Wating for driver event\n", prepadding);
    }
    
    return 0;
}
