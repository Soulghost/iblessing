//
//  macho-module.hpp
//  iblessing-core
//
//  Created by soulghost on 2021/8/26.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef macho_module_hpp
#define macho_module_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <vector>
#include <map>
#include <memory>
#include <iblessing-core/core/symtab/StringTable.hpp>
#include <iblessing-core/core/symtab/SymbolTable.hpp>

NS_IB_BEGIN

struct MachODynamicLibrary {
    std::string name;
    bool upward; // a <-> b (circle)
    bool weak;
};

class MachOModule {
public:
    uint64_t addr;
    uint64_t size;
    
    std::string name;
    std::shared_ptr<StringTable> strtab;
    std::shared_ptr<SymbolTable> symtab;
    
    std::map<uint64_t, std::pair<std::string, std::string>> addr2segInfo;
    std::vector<std::pair<uint64_t, uint32_t>> textPatch;
    std::vector<std::pair<uint64_t, uint64_t>> dataPatch;
};

NS_IB_END

#endif /* macho_module_hpp */
