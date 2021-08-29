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
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/scanner/context/ScannerWorkDirManager.hpp>
#include <memory>
#include <vector>
#include <map>

NS_IB_BEGIN

class MachoLoader {
public:
    MachoLoader();
    ~MachoLoader();
    std::vector<std::shared_ptr<MachOModule>> modules;
    std::map<std::string, std::shared_ptr<MachOModule>> name2module;
    uint64_t loaderOffset;
    
    std::shared_ptr<MachOModule> loadModuleFromFile(std::string filePath);
    uc_engine *uc;
    ScannerWorkDirManager *workDirManager;
};

NS_IB_END

#endif /* macho_loader_hpp */
