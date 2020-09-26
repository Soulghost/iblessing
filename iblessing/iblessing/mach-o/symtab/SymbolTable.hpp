//
//  SymbolTable.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef SymbolTable_hpp
#define SymbolTable_hpp

#include "Object.hpp"
#include "Symbol.hpp"
#include "Vector.hpp"
#include "Map.hpp"
#include <map>

NS_IB_BEGIN

class SymbolTable : public Object {
public:
    virtual ~SymbolTable();
    static SymbolTable* getInstance();
    
    void buildSymbolTable(uint8_t *data, uint64_t nSymbols);
    void buildDynamicSymbolTable(std::vector<struct ib_section_64 *> sectionHeaders, uint8_t *data, uint64_t nSymbols, uint8_t *mappedData);
    void insertSymbol(Symbol *symbol);
    void sync();
    bool relocSymbol(uint64_t addr, uint64_t idx, std::string sectname);
    uint64_t relocQuery(uint64_t addr);
    
    Symbol* getSymbolNearByAddress(uint64_t address);
    Symbol* getSymbolByAddress(uint64_t address);
    Symbol* getSymbolByName(std::string name);
    std::vector<std::pair<std::pair<uint64_t, std::string>, std::pair<uint64_t, uint64_t>>> getAllRelocs();
    
private:
    Map<uint64_t, Symbol *> symbolMap;
    std::map<uint64_t, Symbol *> symbolMapCpp;
    std::map<std::string, Vector<Symbol *>> name2symbol;
    std::vector<std::pair<std::string, struct ib_nlist_64 *>> symbolTable;
    std::vector<Symbol *> symbols;
    std::map<uint64_t, std::pair<Symbol *, std::string>> relocs;
    
    static SymbolTable *_instance;
    SymbolTable();
};

NS_IB_END

#endif /* SymbolTable_hpp */
