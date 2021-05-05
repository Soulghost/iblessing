//
//  SymbolXREFScanner.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/2.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "SymbolXREFScanner.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/scanner/dispatcher/ScannerDispatcher.hpp>
#include <iblessing-core/v2/analyser/xref/FunctionXrefAnalyser.hpp>
#include <set>

using namespace std;
using namespace iblessing;
using namespace iblessing::Analyser;

__attribute__((constructor))
static void scannerRegister() {
    ScannerDispatcher::getInstance()->registerScanner("symbol-xref", []() {
        return new SymbolXREFScanner("symbol-xref", "symbol (function) xref scanner");
    });
};

int SymbolXREFScanner::start() {
    printf("[*] start Symbol (Function) Xref Scanner Finished\n");
    assert(macho != nullptr);
    
    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);
    this->memory = memory;
    
    if (options.find("symbols") == options.end()) {
        cout << termcolor::red;
        cout << StringUtils::format("[-] Error: you should specific symbols by -d 'symbols=<symbol>,<symbol>' or 'symbols=*'");
        cout << termcolor::reset << endl;
        return 1;
    }
    
    string symbolsExpr = options["symbols"];
    vector<string> allSymbols = StringUtils::split(symbolsExpr, ',');
    
    shared_ptr<FunctionXrefAnalyser> xrefAnalyser = FunctionXrefAnalyser::create(macho, memory);
    xrefAnalyser->targetSymbols = allSymbols;
    
    printf("  [*] try to find xrefs for");
    bool first = true;
    for (string symbol : allSymbols) {
        printf("%s%s", first ? "" : ", ", symbol.c_str());
        first = false;
    }
    printf("\n");
    
    xrefAnalyser->start();
    
    for (auto it = xrefAnalyser->xrefs.begin(); it != xrefAnalyser->xrefs.end(); it++) {
        printf("Symbol %s:\n", it->first.c_str());
        for (auto sit = it->second.begin(); sit != it->second.end(); sit++) {
            printf("  [+] 0x%llx ~ 0x%llx: 0x%llx -> 0x%llx\n", sit->startAddr, sit->endAddr, sit->callerAddr, sit->symbolAddr);
        }
        printf("\n");
    }
    
    printf("[+] Symbol (Function) Xref Scanner Finished\n");
    return IB_SUCCESS;
}
