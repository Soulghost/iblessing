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

class MachOLoader;

struct MachODynamicLibrary {
    std::string name;
    std::string path;
    bool upward; // a <-> b (circle)
    bool weak;
};

struct MachOModInitFunc {
    uint64_t addr;
};

struct MachORoutine {
    uint64_t addr;
};

class MachOModule {
public:
    uint64_t addr;
    uint64_t size;
    uint64_t machHeader;
    bool hasInit;
    
    MachOModule();
    
    std::weak_ptr<MachOLoader> loader;
    
    // headers
    uint8_t *mappedBuffer;
    struct ib_dyld_info_command *dyldInfoCommand;
    
    std::string name;
    std::string path;
    std::shared_ptr<StringTable> strtab;
    std::shared_ptr<SymbolTable> symtab;
    std::vector<MachODynamicLibrary> dynamicLibraryDependencies;
    std::vector<MachODynamicLibrary> dynamicLibraryOrdinalList;
    std::vector<MachODynamicLibrary> exportDynamicLibraries;
    std::vector<MachOModInitFunc> modInitFuncs;
    std::vector<MachORoutine> routines;
    
    std::vector<struct ib_segment_command_64 *> segmentHeaders;
    std::vector<struct ib_section_64 *> sectionHeaders;
    std::map<uint64_t, std::pair<std::string, std::string>> addr2segInfo;
    std::vector<std::pair<uint64_t, uint32_t>> textPatch;
    std::vector<std::pair<uint64_t, uint64_t>> dataPatch;
    
    Symbol* getSymbolByName(std::string name, bool checkDependencies);
    
private:
    Symbol* _getSymbolByName(std::string name, bool checkDependencies);
};

NS_IB_END

#endif /* macho_module_hpp */
