//
//  SymbolTable.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "SymbolTable.hpp"
#include "StringTable.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include "DyldSimulator.hpp"

using namespace std;
using namespace iblessing;

SymbolTable* SymbolTable::_instance = nullptr;

SymbolTable::SymbolTable() {
    
}

SymbolTable::~SymbolTable() {
    
}

SymbolTable* SymbolTable::getInstance() {
    assert(false);
    return nullptr;
}

void SymbolTable::sync() {
    std::map<uint64_t, Symbol *> mm(symbolMap.begin(), symbolMap.end());
    this->symbolMapCpp = mm;
}

void SymbolTable::buildExportNodes(DyldLinkContext linkContext, uint64_t linkeditBase, uint32_t export_off, uint32_t export_size) {
    if (export_size == 0) {
        return;
    }
    
    uint8_t *data = (uint8_t *)malloc(export_size);
    uint64_t exportInfoAddr = linkeditBase + export_off;
    assert(uc_mem_read(linkContext.uc, exportInfoAddr, data, export_size) == UC_ERR_OK);
    
    const uint8_t *start = data;
    const uint8_t *end = start + export_size;
    char cummulativeString[32000];
    vector<EntryWithOffset> entries;
    DyldSimulator::processExportNode(start, start, end, cummulativeString, 0, entries);
    exportSymbols.clear();
    for (EntryWithOffset &e : entries) {
        e.entry.address += moduleBase;
        e.entry.other += moduleBase;
        exportSymbols[e.entry.name] = e.entry;
    }
}

void SymbolTable::buildExportNodes(uint8_t *data, uint32_t export_off, uint32_t export_size) {
    if (export_size == 0) {
        return;
    }
    const uint8_t *start = &data[export_off];
    const uint8_t *end = start + export_size;
    char cummulativeString[32000];
    vector<EntryWithOffset> entries;
    DyldSimulator::processExportNode(start, start, end, cummulativeString, 0, entries);
    exportSymbols.clear();
    for (EntryWithOffset &e : entries) {
        e.entry.address += moduleBase;
        e.entry.other += moduleBase;
        exportSymbols[e.entry.name] = e.entry;
    }
}

void SymbolTable::buildSymbolTable(std::string moduleName, uint8_t *data, uint64_t nSymbols) {
    symbols.clear();
    name2symbol.clear();
    symbolMap.clear();
    symbolMapCpp.clear();
    symbolTable.clear();
    
    struct ib_nlist_64 *li = (struct ib_nlist_64 *)data;
    
    for (uint64_t i = 0; i < nSymbols; i++) {
        uint32_t strIdx = li->n_un.n_strx;
        std::string symName = strtab->getStringAtIndex(strIdx);
        Symbol *symbol = new Symbol();
        symbol->name = symName;
        symbol->info = li;
        
        uint8_t type = li->n_type & IB_N_TYPE;
        if ((type == IB_N_SECT || type == IB_N_ABS) && ((type & IB_N_STAB) == 0)) {
            // non-lazy symbol
            // NOTICE: ignore export symbol
            if (li->n_value != 0) {
                // FIXME: symbol base in sharedcache
                if (moduleBase > 0) {
                    li->n_value += DYLD_FIXED_SLIDE;
                }
                if (exportSymbols.size() == 0) {
                    // add symbol directly
                    symbolMap.insert(li->n_value, symbol);
                    name2symbol[symName].pushBack(symbol);
                    symbol->release();
                } else {
                    if (exportSymbols.find(symName) != exportSymbols.end()) {
                        if (exportSymbols[symName].other == li->n_value) {
                            // FIXME: exportSymbol .other
                            symbolMap.insert(li->n_value, symbol);
                            name2symbol[symName].pushBack(symbol);
                            symbol->release();
//                            assert(false);
                        } else {
                            symbolMap.insert(li->n_value, symbol);
                            name2symbol[symName].pushBack(symbol);
                            symbol->release();
                        }
                        exportSymbols.erase(symName);
//                        printf("[*] ignore export symbol %s in %s\n", symName.c_str(), moduleName.c_str());
                    } else {
                        // filter symbol, do nothing?
                    }
                }
            }
        } else if (type == IB_N_INDR) {
            // FIXME: indirect symbols
            string indirectSymbolName = strtab->getStringAtIndex(li->n_value);
            symbol->isIndirect = true;
            symbol->realName = indirectSymbolName;
            name2symbol[symName].pushBack(symbol);
            symbol->release();
        } else {
            if (!symName.empty() && li->n_value > 0) {
//                if (symName == "_malloc") {
//                    
//                }
//                li->n_value += moduleBase;
//                symbolMap.insert(li->n_value, symbol);
//                name2symbol[symName].pushBack(symbol);
//                symbol->release();
            }
            
//            uint64_t idx = 1 + (symbolTable.size() == 0 ? 0 : li - symbolTable.at(0).second);
//            uint64_t addr = -idx;
//            printf("undefined symbol addr 0x%llx\n", addr);
        }
        
        symbolTable.push_back({symName, li});
        symbols.push_back(symbol);
        li += 1;
    }
}

void SymbolTable::buildDynamicSymbolTable(DyldLinkContext linkContext, std::vector<struct ib_section_64 *> sectionHeaders, uint8_t *data, uint64_t nSymbols) {
    uint32_t *dyTableEntries = (uint32_t *)data;
    for (size_t i = 0; i < nSymbols; i++) {
        struct ib_section_64 *symSect = nullptr;
        for (size_t j = sectionHeaders.size() - 1; j >= 0; j--) {
            struct ib_section_64 *sectHeader = sectionHeaders[j];
            
            // only search for lazy symbol sections
            uint32_t flags = sectHeader->flags;
            if ((flags & IB_SECTION_TYPE) != IB_S_SYMBOL_STUBS &&
                (flags & IB_SECTION_TYPE) != IB_S_LAZY_SYMBOL_POINTERS &&
                (flags & IB_SECTION_TYPE) != IB_S_LAZY_DYLIB_SYMBOL_POINTERS &&
                (flags & IB_SECTION_TYPE) != IB_S_NON_LAZY_SYMBOL_POINTERS) {
                continue;
            }
            
            // find symbol's section by index range
            uint32_t startIndex = sectHeader->reserved1;
            if (startIndex > i) {
                continue;
            }
            
            symSect = sectHeader;
            break;
        }
        
        uint32_t symIdx = dyTableEntries[i];
        if (symSect == nullptr) {
            cout << termcolor::red;
            cout << "Error: cannot find dynamic symbol section at index " << symIdx;
            cout << termcolor::reset << endl;
            exit(1);
        }
        
        uint32_t pointerSize = symSect->reserved2 > 0 ? symSect->reserved2 : 8;
        uint64_t pointerAddr = symSect->addr + (i - symSect->reserved1) * pointerSize;
        
        // build symbol
        Symbol *lazySymbol = new Symbol();
        lazySymbol->isStub = true;
        if ((symIdx & (IB_INDIRECT_SYMBOL_LOCAL | IB_INDIRECT_SYMBOL_ABS)) == 0) {
            // stubs
            if (symIdx >= symbolTable.size()) {
                cout << termcolor::red;
                cout << "Error: symbol index out of bound, check if buildSymbolTable has been executed";
                cout << termcolor::reset << endl;
                continue;
            }
            
//            lazySymbol->name = symbolTable.at(symIdx).first;
//            lazySymbol->info = symbolTable.at(symIdx).second;
//            lazySymbol->info->n_value = pointerAddr;
//            symbolMap.insert(pointerAddr, lazySymbol);
//            name2symbol[lazySymbol->name].pushBack(lazySymbol);
        } else {
            switch (symIdx) {
                case IB_INDIRECT_SYMBOL_LOCAL: {
                    uint64_t targetAddr = pointerAddr - (symSect->addr - symSect->offset);
                    uint64_t targetPointer;
                    assert(uc_mem_read(linkContext.uc, targetAddr, &targetPointer, sizeof(uint64_t)) == UC_ERR_OK);
                    
                    Symbol *pointerSymbol = getSymbolByAddress(targetPointer);
                    if (pointerSymbol) {
                        
                    }
                    break;
                }
                case IB_INDIRECT_SYMBOL_ABS: {
                    
                    break;
                }
                default: {
                    
                    break;
                }
            }
        }
        lazySymbol->release();
    }
}

void SymbolTable::buildDynamicSymbolTable(std::vector<struct ib_section_64 *> sectionHeaders, uint8_t *data, uint64_t nSymbols, uint8_t *mappedData) {
    uint32_t *dyTableEntries = (uint32_t *)data;
    for (size_t i = 0; i < nSymbols; i++) {
        struct ib_section_64 *symSect = nullptr;
        for (size_t j = sectionHeaders.size() - 1; j >= 0; j--) {
            struct ib_section_64 *sectHeader = sectionHeaders[j];
            
            // only search for lazy symbol sections
            uint32_t flags = sectHeader->flags;
            if ((flags & IB_SECTION_TYPE) != IB_S_SYMBOL_STUBS &&
                (flags & IB_SECTION_TYPE) != IB_S_LAZY_SYMBOL_POINTERS &&
                (flags & IB_SECTION_TYPE) != IB_S_LAZY_DYLIB_SYMBOL_POINTERS &&
                (flags & IB_SECTION_TYPE) != IB_S_NON_LAZY_SYMBOL_POINTERS) {
                continue;
            }
            
            // find symbol's section by index range
            uint32_t startIndex = sectHeader->reserved1;
            if (startIndex > i) {
                continue;
            }
            
            symSect = sectHeader;
            break;
        }
        
        uint32_t symIdx = dyTableEntries[i];
        if (symSect == nullptr) {
            cout << termcolor::red;
            cout << "Error: cannot find dynamic symbol section at index " << symIdx;
            cout << termcolor::reset << endl;
            exit(1);
        }
        
        uint32_t pointerSize = symSect->reserved2 > 0 ? symSect->reserved2 : 8;
        uint64_t pointerAddr = symSect->addr + (i - symSect->reserved1) * pointerSize;
        
        // build symbol
        Symbol *lazySymbol = new Symbol();
        lazySymbol->isStub = true;
        if ((symIdx & (IB_INDIRECT_SYMBOL_LOCAL | IB_INDIRECT_SYMBOL_ABS)) == 0) {
            // stubs
            if (symIdx >= symbolTable.size()) {
                cout << termcolor::red;
                cout << "Error: symbol index out of bound, check if buildSymbolTable has been executed";
                cout << termcolor::reset << endl;
                continue;
            }
            
//            lazySymbol->name = symbolTable.at(symIdx).first;
//            lazySymbol->info = symbolTable.at(symIdx).second;
//            lazySymbol->info->n_value = pointerAddr;
//            symbolMap.insert(pointerAddr, lazySymbol);
//            name2symbol[lazySymbol->name].pushBack(lazySymbol);
        } else {
            switch (symIdx) {
                case IB_INDIRECT_SYMBOL_LOCAL: {
                    uint64_t targetAddr = pointerAddr - (symSect->addr - symSect->offset);
                    uint64_t targetPointer = *(uint64_t *)(mappedData + targetAddr);
                    
                    Symbol *pointerSymbol = getSymbolByAddress(targetPointer);
                    if (pointerSymbol) {
                        
                    }
                    break;
                }
                case IB_INDIRECT_SYMBOL_ABS: {
                    
                    break;
                }
                default: {
                    
                    break;
                }
            }
        }
        lazySymbol->release();
    }
}

bool SymbolTable::relocSymbol(uint64_t addr, uint64_t idx, ib_section_64 *section) {
    if (idx >= symbols.size()) {
        return false;
    }
    
    Symbol *symbol = symbols[idx];
    if (symbol->name.length() == 0) {
        return false;
    }
    
    symbolMap.insert(addr, symbol);
    name2symbol[symbol->name].pushBack(symbol);
    
    SymbolRelocation relocation = SymbolRelocation();
    /**
     ib_scattered_relocation_info *info;
     uint64_t relocAddr;
     uint64_t relocValue;
     uint64_t relocSize;
     Symbol *relocSymbol;
     ib_section_64 *relocSection;
     */
    relocation.relocAddr = addr;
    relocation.relocValue = symbol->info->n_value;
    relocation.relocSize = 8;
    relocation.relocSymbol = symbol;
    relocation.relocSection = section;
    relocs[addr] = relocation;
    return true;
}

uint64_t SymbolTable::relocQuery(uint64_t addr) {
    if (relocs.find(addr) != relocs.end()) {
        Symbol *symbol = relocs[addr].relocSymbol;
        return symbol->info->n_value;
    }
    
    return addr;
}

Symbol* SymbolTable::getSymbolByAddress(uint64_t address) {
    if (symbolMap.find(address) != symbolMap.end()){
        return symbolMap.at(address);
    }
    return nullptr;
}

Symbol* SymbolTable::getSymbolNearByAddress(uint64_t address) {
    if (symbolMapCpp.empty()) {
        return nullptr;
    }
    auto it = symbolMapCpp.lower_bound(address);
    if (it->first == address) {
        return it->second;
    } else if (it != symbolMapCpp.begin()) {
        return (--it)->second;
    } else {
        return nullptr;
    }
}


Symbol* SymbolTable::getSymbolByName(std::string name) {
    if (indirectSymbolMap.find(name) != indirectSymbolMap.end()) {
        name = indirectSymbolMap[name].name;
    }
    if (name2symbol.find(name) != name2symbol.end() &&
        name2symbol[name].size() > 0) {
        return name2symbol[name].at(0);
    }
    return nullptr;
}

vector<SymbolRelocation> SymbolTable::getAllRelocs() {
    vector<SymbolRelocation> allRelocs;
    for (auto it : relocs) {
        allRelocs.push_back(it.second);
    }
    return allRelocs;
}

void SymbolTable::insertSymbol(Symbol *symbol) {
    if (symbol == nullptr) {
        return;
    }
    
    if (symbol->info != nullptr && symbol->info->n_value != 0) {
        symbolMap.insert(symbol->info->n_value, symbol);
    }
    
    if (symbol->name.length() > 0) {
        name2symbol[symbol->name].pushBack(symbol);
    }
}
