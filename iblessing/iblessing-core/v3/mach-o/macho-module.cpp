//
//  macho-module.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/8/26.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "macho-module.hpp"
#include "macho-loader.hpp"

using namespace std;
using namespace iblessing;

Symbol* MachOModule::getSymbolByName(std::string name, bool checkDependencies) {
    Symbol *sym = symtab->getSymbolByName(name);
    shared_ptr<MachOLoader> _loader = loader.lock();
    assert(_loader != nullptr);
    if (!sym && checkDependencies) {
        for (MachODynamicLibrary &library : exportDynamicLibraries) {
            shared_ptr<MachOModule> targetModule = _loader->findModuleByName(library.name);
            if (targetModule == nullptr) {
                continue;
            }
            sym = targetModule->getSymbolByName(name, false);
            if (sym) {
                break;
            }
        }
    }
    return sym;
}
