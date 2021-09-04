//
//  aarch64-machine.hpp
//  iblessing-core
//
//  Created by soulghost on 2021/9/2.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef aarch64_machine_hpp
#define aarch64_machine_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v3/mach-o/macho-module.hpp>
#include <iblessing-core/v3/kernel/syscall/aarch64-svc-manager.hpp>

NS_IB_BEGIN

class Aarch64Machine {
public:
    uc_engine *uc;
    std::shared_ptr<Aarch64SVCManager> svcManager;
    
    int callModule(std::shared_ptr<MachOModule> module, std::string symbolName = "");
};

NS_IB_END

#endif /* aarch64_machine_hpp */
