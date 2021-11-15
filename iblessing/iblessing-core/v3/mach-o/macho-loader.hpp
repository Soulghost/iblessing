//
//  macho-loader.hpp
//  iblessing-core
//
//  Created by soulghost on 2021/8/26.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef macho_loader_hpp
#define macho_loader_hpp

#include <iblessing-core/v3/mach-o/macho-module.hpp>
#include <iblessing-core/v3/kernel/syscall/aarch64-svc-manager.hpp>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/scanner/context/ScannerWorkDirManager.hpp>
#include <iblessing-core/v3/memory/macho-memory-manager.hpp>
#include <iblessing-core/v3/dyld/dyld-sharedcache-loader.hpp>
#include <memory>
#include <vector>
#include <map>
#include <set>

NS_IB_BEGIN

class Aarch64Machine;

class MachOLoader : public std::enable_shared_from_this<MachOLoader> {
public:
    MachOLoader();
    ~MachOLoader();
    std::vector<std::shared_ptr<MachOModule>> modules;
    std::map<std::string, std::shared_ptr<MachOModule>> name2module;
    std::map<uint64_t, std::shared_ptr<MachOModule>> addr2module;
    uint64_t loaderOffset;
    
    std::shared_ptr<MachOModule> loadModuleFromFile(std::string filePath);
    uc_engine *uc;
    ScannerWorkDirManager *workDirManager;
    std::shared_ptr<MachOMemoryManager> memoryManager;
    std::shared_ptr<Aarch64SVCManager> svcManager;
    std::weak_ptr<Aarch64Machine> machine;
    std::shared_ptr<MachOModule> findModuleByName(std::string moduleName);
    std::shared_ptr<MachOModule> findModuleByAddr(uint64_t addr);
    Symbol * getSymbolByAddress(uint64_t addr);
    void printImageList();
    
protected:
    std::shared_ptr<MachOModule> _loadModuleFromFile(DyldLinkContext linkContext, std::string filePath, bool loadDylibs);
    std::shared_ptr<MachOModule> _loadModuleFromFileUsingSharedCache(DyldLinkContext linkContext, std::string filePath, bool loadDylibs);
    std::set<uint64_t> dyldInitHandlers;
    std::set<uint64_t> dyldBoundHandlers;
};

NS_IB_END

#endif /* macho_loader_hpp */
