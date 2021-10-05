//
//  dyld.cpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "dyld.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v3/mach-o/macho-loader.hpp>

using namespace std;
using namespace iblessing;

std::map<std::string, DyldBindHook> Dyld::bindHooks;

static uintptr_t read_uleb128(const uint8_t*& p, const uint8_t* end)
{
    uint64_t result = 0;
    int         bit = 0;
    do {
        if (p == end)
            printf("[-] malformed uleb128\n");

        uint64_t slice = *p & 0x7f;

        if (bit > 63)
            printf("[-] uleb128 too big for uint64, bit=%d, result=0x%0llX\n", bit, result);
        else {
            result |= (slice << bit);
            bit += 7;
        }
    } while (*p++ & 0x80);
    return result;
}

static intptr_t read_sleb128(const uint8_t*& p, const uint8_t* end)
{
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do {
        if (p == end)
            printf("[-] malformed sleb128\n");
        byte = *p++;
        result |= (((int64_t)(byte & 0x7f)) << bit);
        bit += 7;
    } while (byte & 0x80);
    // sign extend negative numbers
    if ( (byte & 0x40) != 0 )
        result |= (-1LL) << bit;
    return result;
}

shared_ptr<Dyld> Dyld::create(shared_ptr<MachO> macho, shared_ptr<Memory> memory, shared_ptr<Objc> objc) {
    return make_shared<Dyld>(macho, memory, objc);
}

void Dyld::doBindAll(DyldBindHandler handler) {
    shared_ptr<VirtualMemory> fvm = memory->fileMemory;
    shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    shared_ptr<SymbolTable> symtab = macho->context->symtab;
    DyldSimulator::eachBind(fvm->mappedFile, fvm->segmentHeaders, fvm->dyldinfo, [&](uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, int64_t libraryOrdinal, const char *msg) {
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

uint64_t Dyld::bindAt(shared_ptr<MachOModule> module, shared_ptr<MachOLoader> loader, int64_t libraryOrdinal, const char *symbolName, uint64_t addr, uint64_t addend, uint8_t type) {
    uc_engine *uc = loader->uc;
    shared_ptr<MachOModule> targetModule = nullptr;
    if (libraryOrdinal <= 0) {
        switch (libraryOrdinal) {
            case IB_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: {
                assert(false);
                break;
            }
            case IB_BIND_SPECIAL_DYLIB_SELF: {
                targetModule = module;
                break;
            }
            default: {
                assert(false);
            }
        }
    } else {
        if (libraryOrdinal - 1 >= module->dynamicLibraryOrdinalList.size()) {
            cout << termcolor::yellow << StringUtils::format("[-] MachOLoader - Warn: eachBind error for %s, invalid libraryOrdinal %lld, total dylibs %lu", module->name.c_str(), libraryOrdinal, module->dynamicLibraryOrdinalList.size());
            cout << termcolor::reset << endl;
            return 0;
        }
        
        MachODynamicLibrary &library = module->dynamicLibraryOrdinalList[libraryOrdinal - 1];
        string libraryName = library.name;
        targetModule = loader->findModuleByName(libraryName);
    }
    assert(targetModule != nullptr);
    
    set<pair<string, string>> symbolNotFoundErrorSet;
    if (strcmp(symbolName, "_strncmp") == 0) {
        printf("");
    }
    Symbol *sym = targetModule->getSymbolByName(symbolName, true);
    if (!sym) {
        pair<string, string> errorPattern = {symbolName, targetModule->name};
        if (symbolNotFoundErrorSet.find(errorPattern) == symbolNotFoundErrorSet.end()) {
            cout << termcolor::yellow << StringUtils::format("[-] MachOLoader - Warn: eachBind cannot find symbol %s in %s\n", symbolName, targetModule->name.c_str());
            cout << termcolor::reset << endl;
            symbolNotFoundErrorSet.insert(errorPattern);
        }
        return 0;
    }
    assert(sym->info);
    assert(sym->info->n_value > 0);
    switch (type) {
        case IB_BIND_TYPE_POINTER: {
            if (strcmp(symbolName, "_strncmp") == 0) {
                printf("");
            }
            
            uint64_t bindToPtrAddr = addr + addend;
            uint64_t symbolAddr = sym->info->n_value;
            assert(symbolAddr != 0);
            
            if (bindHooks.find(symbolName) != bindHooks.end()) {
                symbolAddr = bindHooks[symbolName](symbolName, symbolAddr);
            }
            assert(uc_mem_write(uc, bindToPtrAddr, &symbolAddr, 8) == UC_ERR_OK);
            printf("[+] bind %s(%s) at 0x%llx to 0x%llx(%s)\n", symbolName, targetModule->name.c_str(), symbolAddr, bindToPtrAddr, module->name.c_str());
            return symbolAddr;
        }
        case IB_BIND_TYPE_TEXT_ABSOLUTE32: {
            assert(false);
            return 0;
        }
        default:
            assert(false);
            break;
    }
    return 0;
}

uint64_t Dyld::doFastLazyBind(shared_ptr<MachOModule> module, shared_ptr<MachOLoader> loader, uint64_t lazyBindingInfoOffset) {
    uint8_t *buffer = module->mappedBuffer;
    uint8_t *lazyBindBegin = buffer + module->dyldInfoCommand->lazy_bind_off;
    uint8_t *lazyInfoEnd = lazyBindBegin + module->dyldInfoCommand->lazy_bind_size;
    assert(lazyBindingInfoOffset < module->dyldInfoCommand->lazy_bind_size);
    
    bool done = false;
    bool doneAfterBind;
    uint8_t segIndex = 0;
    uint64_t segOffset = 0;
    const char *symbolName;
    int ordinal = 0;
    uint8_t type = IB_BIND_TYPE_POINTER;
    const uint8_t* p = lazyBindBegin + lazyBindingInfoOffset;
    while ( !done && (p < lazyInfoEnd) ) {
        uint8_t immediate = *p & IB_BIND_IMMEDIATE_MASK;
        uint8_t opcode = *p & IB_BIND_OPCODE_MASK;
        ++p;
        switch (opcode) {
            case IB_BIND_OPCODE_DONE:
                doneAfterBind = false;
                return true;
                break;
            case IB_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                ordinal = immediate;
                break;
            case IB_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                ordinal = (int)read_uleb128(p, lazyInfoEnd);
                break;
            case IB_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                // the special ordinals are negative numbers
                if ( immediate == 0 )
                    ordinal = 0;
                else {
                    int8_t signExtended = IB_BIND_OPCODE_MASK | immediate;
                    ordinal = signExtended;
                }
                break;
            case IB_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbolName = (char*)p;
                while (*p != '\0')
                    ++p;
                ++p;
                break;
            case IB_BIND_OPCODE_SET_TYPE_IMM:
                break;
            case IB_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segIndex  = immediate;
                segOffset = read_uleb128(p, lazyInfoEnd);
                break;
            case IB_BIND_OPCODE_DO_BIND: {
                doneAfterBind = ((*p & IB_BIND_OPCODE_MASK) == IB_BIND_OPCODE_DONE);
                lazyBindingInfoOffset += p - lazyBindBegin;
                uint64_t address = module->segmentHeaders[segIndex]->vmaddr + segOffset;
                uint64_t result = bindAt(module, loader, ordinal, symbolName, address, 0, type);
                return result;
            }
            case IB_BIND_OPCODE_SET_ADDEND_SLEB:
            case IB_BIND_OPCODE_ADD_ADDR_ULEB:
            case IB_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            case IB_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            case IB_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            default:
                return 0;
        }
    }
    return 0;
}
