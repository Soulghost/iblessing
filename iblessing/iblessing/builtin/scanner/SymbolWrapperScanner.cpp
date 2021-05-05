//
//  SymbolWrapperScanner.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "SymbolWrapperScanner.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/scanner/dispatcher/ScannerDispatcher.hpp>
#include <iblessing-core/v2/analyser/wrapper/SimpleWrapperAnalyser.hpp>
#include <iblessing/builtin/serialization/SymbolWrapperSerializationManager.hpp>
#include <set>

using namespace std;
using namespace iblessing;
using namespace iblessing::Analyser;

__attribute__((constructor))
static void scannerRegister() {
    ScannerDispatcher::getInstance()->registerScanner("symbol-wrapper", []() {
        return new SymbolWrapperScanner("symbol-wrapper", "symbol wrapper scanner");
    });
};

int SymbolWrapperScanner::start() {
    printf("[*] start Symbol Wrapper Scanner Finished\n");
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
    
    shared_ptr<SimpleWrapperAnalyser> wrapperAnalyser = SimpleWrapperAnalyser::create(macho, memory);
    wrapperAnalyser->targetSymbols = allSymbols;
    wrapperAnalyser->start();
    
    printf("[*] Step 3. serialize wrapper graph to file\n");
    // setup recordPath
    string graphPath = StringUtils::path_join(outputPath, fileName + "_wrapper-graph.iblessing.txt");
    if (SymbolWrapperSerializationManager::createReportFromAntiWrapper(graphPath, wrapperAnalyser->antiWrapper, wrapperAnalyser->symbol2proto)) {
        printf("\t[*] wrapper graph file saved to %s\n", graphPath.c_str());
    } else {
        printf("\t[*] error: cannot save to path %s\n", graphPath.c_str());
    }
    
    printf("[*] Symbol Wrapper Scanner finished\n");
    return IB_SUCCESS;
}
