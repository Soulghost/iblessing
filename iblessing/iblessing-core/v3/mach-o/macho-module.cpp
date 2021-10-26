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

MachOModule::MachOModule() {
    hasInit = false;
}

Symbol* MachOModule::getSymbolByName(std::string name, bool checkDependencies) {
    Symbol *sym = _getSymbolByName(name, checkDependencies);
    if (!sym) {
        return nullptr;
    }
    if (sym->isIndirect) {
        Symbol *resolvedSymbol = _getSymbolByName(sym->realName, checkDependencies);
        if (resolvedSymbol) {
            return resolvedSymbol;
        }
    }
    return sym;
}

Symbol* MachOModule::_getSymbolByName(std::string name, bool checkDependencies) {
    Symbol *sym = symtab->getSymbolByName(name);
    if (sym) {
        if (sym->isIndirect) {
            return sym;
        }
    }
    shared_ptr<MachOLoader> _loader = loader.lock();
    assert(_loader != nullptr);
    if (!sym && checkDependencies) {
        for (MachODynamicLibrary &library : exportDynamicLibraries) {
            shared_ptr<MachOModule> targetModule = _loader->findModuleByName(library.name);
            if (targetModule == nullptr) {
                continue;
            }
            sym = targetModule->getSymbolByName(name, false);
            if (sym && !sym->isStub) {
                break;
            }
        }
        if (!sym) {
            // find in modules
            for (shared_ptr<MachOModule> module : _loader->modules) {
                sym = module->getSymbolByName(name, false);
                if (sym && !sym->isStub) {
                    break;
                }
            }
        }
    }
    return sym;
}

Symbol* MachOModule::getSymbolByAddress(uint64_t addr) {
    return this->symtab->getSymbolByAddress(addr);
}

Symbol* MachOModule::getSymbolNearByAddress(uint64_t addr) {
    return this->symtab->getSymbolNearByAddress(addr);
}
