//
//  SymbolTable.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef SymbolTable_hpp
#define SymbolTable_hpp

#include <map>
#include <set>
#include <iblessing-core/infra/Object.hpp>
#include <iblessing-core/infra/Vector.hpp>
#include <iblessing-core/infra/Map.hpp>
#include <iblessing-core/core/symtab/Symbol.hpp>
#include <iblessing-core/core/symtab/StringTable.hpp>
#include <iblessing-core/core/polyfill/mach-universal.hpp>
#include <iblessing-core/core/polyfill/mach-machine.h>
#include <iblessing-core/core/dyld/DyldSimulator.hpp>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v3/dyld/dyld-sharedcache-loader.hpp>

NS_IB_BEGIN

typedef struct SymbolRelocation {
    ib_scattered_relocation_info *info;
    uint64_t relocAddr;
    uint64_t relocValue;
    uint64_t relocSize;
    Symbol *relocSymbol;
    ib_section_64 *relocSection;
} SymbolRelocation;

typedef struct IndirectSymbol {
    std::string name;
} IndirectSymbol;

class SymbolTable : public Object {
public:
    std::shared_ptr<StringTable> strtab;
    uint64_t moduleBase;
    
    SymbolTable(std::shared_ptr<StringTable> strtab) : strtab(strtab) {};
    virtual ~SymbolTable();
    static SymbolTable* getInstance();
    
    void buildExportNodes(DyldLinkContext linkContext, uint32_t export_off, uint32_t export_size);
    void buildExportNodes(uint8_t *data, uint32_t export_off, uint32_t export_size);
    
    void buildSymbolTable(std::string moduleName, uint8_t *data, uint64_t nSymbols);
    
    void buildDynamicSymbolTable(DyldLinkContext linkContext, std::vector<struct ib_section_64 *> sectionHeaders, uint8_t *data, uint64_t nSymbols);
    void buildDynamicSymbolTable(std::vector<struct ib_section_64 *> sectionHeaders, uint8_t *data, uint64_t nSymbols, uint8_t *mappedData);
    void insertSymbol(Symbol *symbol);
    void sync();
    bool relocSymbol(uint64_t addr, uint64_t idx, ib_section_64 *section);
    uint64_t relocQuery(uint64_t addr);
    
    Symbol* getSymbolNearByAddress(uint64_t address);
    Symbol* getSymbolByAddress(uint64_t address);
    Symbol* getSymbolByName(std::string name);
    std::vector<SymbolRelocation> getAllRelocs();
private:
    Map<uint64_t, Symbol *> symbolMap;
    std::map<std::string, Entry> exportSymbols;
    std::map<std::string, IndirectSymbol> indirectSymbolMap;
    std::map<uint64_t, Symbol *> symbolMapCpp;
    std::map<std::string, Vector<Symbol *>> name2symbol;
    std::vector<std::pair<std::string, struct ib_nlist_64 *>> symbolTable;
    std::vector<Symbol *> symbols;
    std::map<uint64_t, SymbolRelocation> relocs;
    
    static SymbolTable *_instance;
    SymbolTable();
};

NS_IB_END

#endif /* SymbolTable_hpp */
