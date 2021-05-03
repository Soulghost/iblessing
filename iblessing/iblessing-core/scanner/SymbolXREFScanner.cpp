//
//  SymbolXREFScanner.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/2.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "SymbolXREFScanner.hpp"
#include <iblessing/util/termcolor.h>
#include <iblessing/util/StringUtils.h>
#include "VirtualMemory.hpp"
#include "ARM64Runtime.hpp"
#include "ARM64Disasembler.hpp"
#include "SymbolTable.hpp"
#include <set>
#include "ScannerDispatcher.hpp"

using namespace std;
using namespace iblessing;

__attribute__((constructor))
static void scannerRegister() {
    ScannerDispatcher::getInstance()->registerScanner("symbol-xref", []() {
        return new SymbolXREFScanner("symbol-xref", "symbol xref scanner");
    });
};

int SymbolXREFScanner::start() {
    return 1;
}
