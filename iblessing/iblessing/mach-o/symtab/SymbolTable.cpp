//
//  SymbolTable.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "SymbolTable.hpp"
#include "StringTable.hpp"
#include "termcolor.h"

using namespace std;
using namespace iblessing;

SymbolTable* SymbolTable::_instance = nullptr;

SymbolTable::SymbolTable() {
    Symbol *sym = new Symbol();
    sym->name = "_test";
    symbolMap.insert(0x1040143D0, sym);
    sym->release();
}

SymbolTable::~SymbolTable() {
    
}

SymbolTable* SymbolTable::getInstance() {
    if (SymbolTable::_instance == nullptr) {
        SymbolTable::_instance = new SymbolTable();
    }
    return SymbolTable::_instance;
}

void SymbolTable::sync() {
    std::map<uint64_t, Symbol *> mm(symbolMap.begin(), symbolMap.end());
    this->symbolMapCpp = mm;
}

void SymbolTable::buildSymbolTable(uint8_t *data, uint64_t nSymbols) {
    symbols.clear();
    name2symbol.clear();
    symbolMap.clear();
    symbolMapCpp.clear();
    symbolTable.clear();
    
    struct ib_nlist_64 *li = (struct ib_nlist_64 *)data;
    StringTable *strtab = StringTable::getInstance();
    
    for (uint64_t i = 0; i < nSymbols; i++) {
        uint32_t strIdx = li->n_un.n_strx;
        std::string symName = strtab->getStringAtIndex(strIdx);
        Symbol *symbol = new Symbol();
        symbol->name = symName;
        symbol->info = li;
        
        if ((li->n_type & IB_N_STAB) == 0) {
            uint64_t symAddr = li->n_value;
            // non-lazy symbol
            if (symAddr != 0) {
                symbolMap.insert(symAddr, symbol);
                name2symbol[symName].pushBack(symbol);
                symbol->release();
            }
        } else {
            if (!symName.empty() && li->n_value > 0) {
                symbolMap.insert(li->n_value, symbol);
                name2symbol[symName].pushBack(symbol);
                symbol->release();
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
        if ((symIdx & (IB_INDIRECT_SYMBOL_LOCAL | IB_INDIRECT_SYMBOL_ABS)) == 0) {
            // stubs
            if (symIdx >= symbolTable.size()) {
                cout << termcolor::red;
                cout << "Error: symbol index out of bound, check if buildSymbolTable has been executed";
                cout << termcolor::reset << endl;
                continue;
            }
            
            lazySymbol->name = symbolTable.at(symIdx).first;
            lazySymbol->info = symbolTable.at(symIdx).second;
            lazySymbol->info->n_value = pointerAddr;
            symbolMap.insert(pointerAddr, lazySymbol);
            name2symbol[lazySymbol->name].pushBack(lazySymbol);
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

bool SymbolTable::relocSymbol(uint64_t addr, uint64_t idx, string sectname) {
    if (idx >= symbols.size()) {
        return false;
    }
    
    Symbol *symbol = symbols[idx];
    if (symbol->name.length() == 0) {
        return false;
    }
    
    symbolMap.insert(addr, symbol);
    name2symbol[symbol->name].pushBack(symbol);
    relocs[addr] = {symbol, sectname};
    return true;
}

uint64_t SymbolTable::relocQuery(uint64_t addr) {
    if (relocs.find(addr) != relocs.end()) {
        Symbol *symbol = relocs[addr].first;
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
    if (name2symbol.find(name) != name2symbol.end() &&
        name2symbol[name].size() > 0) {
        return name2symbol[name].at(0);
    }
    return nullptr;
}

vector<pair<pair<uint64_t, string>, pair<uint64_t, uint64_t>>> SymbolTable::getAllRelocs() {
    vector<pair<pair<uint64_t, string>, pair<uint64_t, uint64_t>>> allRelocs;
    for (auto it : relocs) {
        allRelocs.push_back({{it.first, it.second.second}, {it.second.first->info->n_value, 8}});
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
