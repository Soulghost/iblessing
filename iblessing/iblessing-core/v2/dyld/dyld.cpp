//
//  dyld.cpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "dyld.hpp"
#include <iblessing-core/v2/util/StringUtils.h>

using namespace std;
using namespace iblessing;

shared_ptr<Dyld> Dyld::create(shared_ptr<MachO> macho, shared_ptr<Memory> memory, shared_ptr<Objc> objc) {
    return make_shared<Dyld>(macho, memory, objc);
}

void Dyld::doBindAll(DyldBindHandler handler) {
    shared_ptr<VirtualMemory> fvm = memory->fileMemory;
    shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    shared_ptr<SymbolTable> symtab = macho->context->symtab;
    DyldSimulator::eachBind(fvm->mappedFile, fvm->segmentHeaders, fvm->dyldinfo, [&](uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, uint64_t libraryOrdinal, const char *msg) {
        uint64_t symbolAddr = addr + addend;
        
        // load non-lazy symbols
        vm2->write64(symbolAddr, symbolAddr);
        
        // record class info
        if (objc) {
            shared_ptr<ObjcRuntime> rt = objc->getRuntime();
            if (string(symbolName).rfind("_OBJC_CLASS_$") == 0) {
                string className;
                vector<string> parts = StringUtils::split(symbolName, '_');
                if (parts.size() > 1) {
                    className = parts[parts.size() - 1];
                } else {
                    className = symbolName;
                }
                
                ObjcClassRuntimeInfo *externalClassInfo = rt->getClassInfoByName(className);
                if (!externalClassInfo) {
                    externalClassInfo = new ObjcClassRuntimeInfo();
                    externalClassInfo->className = className;
                    externalClassInfo->isExternal = true;
                    externalClassInfo->address = symbolAddr;
                    rt->name2ExternalClassRuntimeInfo[externalClassInfo->className] = externalClassInfo;
                    rt->runtimeInfo2address[externalClassInfo] = symbolAddr;
                }
                rt->externalClassRuntimeInfo[symbolAddr] = externalClassInfo;
                
            } else if (strcmp(symbolName, "__NSConcreteGlobalBlock") == 0 ||
                       strcmp(symbolName, "__NSConcreteStackBlock") == 0) {
                rt->blockISAs.insert(symbolAddr);
            }
        }
        
        // record symbol
        Symbol *sym = new Symbol();
        sym->name = symbolName;
        struct ib_nlist_64 *nl = (struct ib_nlist_64 *)calloc(1, sizeof(ib_nlist_64));
        nl->n_value = symbolAddr;
        sym->info = nl;
        symtab->insertSymbol(sym);
        
        if (handler) {
            handler(addr, type, symbolName, symbolFlags, addend, libraryOrdinal, msg);
        }
    });
}
