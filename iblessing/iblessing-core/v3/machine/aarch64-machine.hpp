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
#include <iblessing-core/v3/mach-o/macho-loader.hpp>
#include <iblessing-core/v3/kernel/syscall/aarch64-svc-manager.hpp>

NS_IB_BEGIN

#define UnicornStackTopAddr      0x300000000

typedef struct ib_module_init_env {
    uint64_t varsAddr;
} ib_module_init_env;

class Aarch64Machine {
public:
    uc_engine *uc;
    std::shared_ptr<Aarch64SVCManager> svcManager;
    std::shared_ptr<MachOLoader> loader;
    
    int callModule(std::shared_ptr<MachOModule> module, std::string symbolName = "");
    void initModule(std::shared_ptr<MachOModule> module, ib_module_init_env &env);
    void initModule(std::shared_ptr<MachOModule> module);
    void setErrno(int no);
    void setErrnoAddr(uint64_t addr);
    
protected:
    ib_module_init_env defaultEnv;
    uint64_t errnoAddr;
};

NS_IB_END

#endif /* aarch64_machine_hpp */
