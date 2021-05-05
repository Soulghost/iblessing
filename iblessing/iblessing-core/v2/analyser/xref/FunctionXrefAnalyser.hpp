//
//  FunctionXrefAnalyser.hpp
//  iblessing
//
//  Created by Soulghost on 2021/5/3.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef SymbolXrefAnalyser_hpp
#define SymbolXrefAnalyser_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/scanner/driver/ScannerDisassemblyDriver.hpp>
#include <iblessing-core/v2/analyser/wrapper/AntiWrapper.hpp>
#include <iblessing-core/v2/analyser/wrapper/FunctionPrototype.hpp>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>

namespace iblessing {
namespace Analyser {

struct SymbolXREF {
    std::string name;
    uint64_t startAddr;
    uint64_t endAddr;
    uint64_t symbolAddr;
    uint64_t callerAddr;
    
    bool operator < (const SymbolXREF &rhs) const {
        return startAddr < rhs.startAddr;
    }
};

class FunctionXrefAnalyser {
public:
    FunctionXrefAnalyser(std::shared_ptr<MachO> macho, std::shared_ptr<Memory> memory) : macho(macho), memory(memory) {}
    static std::shared_ptr<FunctionXrefAnalyser> create(std::shared_ptr<MachO> macho, std::shared_ptr<Memory> memory);
    
    std::shared_ptr<ScannerDisassemblyDriver> disasmDriver;
    std::vector<std::string> targetSymbols;
    std::map<std::string, std::set<SymbolXREF>> xrefs;
    
    ib_return_t start();
protected:
    std::shared_ptr<MachO> macho;
    std::shared_ptr<Memory> memory;
    
    std::map<std::string, std::set<SymbolXREF>> currentXREFs;
    uint64_t funcStartCursor = 0;
    uint8_t progressCur = 0;
};

};
};

#endif /* SymbolXrefAnalyser_hpp */
