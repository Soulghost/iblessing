//
//  SimpleWrapperAnalyser.hpp
//  iblessing
//
//  Created by Soulghost on 2021/5/3.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef SimpleWrapperAnalyser_hpp
#define SimpleWrapperAnalyser_hpp

#include <iblessing/common/ibtypes.h>
#include <iblessing/scanner/driver/ScannerDisassemblyDriver.hpp>
#include <iblessing/analyser/wrapper/AntiWrapper.hpp>
#include <iblessing/analyser/wrapper/FunctionPrototype.hpp>
#include <iblessing/mach-o/mach-o.hpp>
#include <iblessing/memory/memory.hpp>
#include <iblessing/vendor/unicorn/unicorn.h>

namespace iblessing {
namespace Analyser {

class SimpleWrapperAnalyser {
public:
    SimpleWrapperAnalyser(std::shared_ptr<MachO> macho, std::shared_ptr<Memory> memory) : macho(macho), memory(memory) {
        init();
    }
    static std::shared_ptr<SimpleWrapperAnalyser> create(std::shared_ptr<MachO> macho, std::shared_ptr<Memory> memory);
    void init();
    
    std::shared_ptr<ScannerDisassemblyDriver> disasmDriver;
    std::vector<std::string> targetSymbols;
    
    ib_return_t start();
    std::pair<bool, std::string> isWrappedCall(uint64_t address);
    AntiWrapperArgs performWrapperTransform(uint64_t addr, AntiWrapperArgs args);
    
protected:
    std::shared_ptr<MachO> macho;
    std::shared_ptr<Memory> memory;
    pthread_mutex_t wrapperLock;
    uc_engine *uc;
    uc_hook memexp_hook;
    uc_context *ctx;
    std::map<std::string, FunctionProtoType> symbol2proto;
    
    uint64_t funcStartCursor = 0;
    uint8_t progressCur = 0;
    bool hasMemLoader = false;
    AntiWrapper antiWrapper;
    AntiWrapperRegLinkGraph currentGraph;
};

};
};

#endif /* SimpleWrapperAnalyser_hpp */
