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
#include <iblessing-core/v3/posix/pthread/pthread_kern.hpp>

NS_IB_BEGIN

#define UnicornStackTopAddr      0x300000000

typedef struct ib_module_init_env {
    uint64_t environAddr;
    uint64_t varsAddr;
    uint64_t appleAddr;
} ib_module_init_env;

typedef struct ib_pendding_thread {
    uint64_t func;
    uint64_t func_arg;
    uint64_t stack;
    uint64_t pthread;
    uint32_t flags;
    uc_context *exit_ctx;
    uint64_t tsd;
    // init state
    uint64_t pc;
    uint64_t sp;
    uint64_t x[8];
} ib_pendding_thread;

class Aarch64Machine : public std::enable_shared_from_this<Aarch64Machine> {
public:
    uc_engine *uc;
    std::shared_ptr<Aarch64SVCManager> svcManager;
    std::shared_ptr<MachOLoader> loader;
    std::shared_ptr<PthreadKern> threadManager;
    
    int callModule(std::shared_ptr<MachOModule> module, std::string symbolName = "");
    void initModule(std::shared_ptr<MachOModule> module, ib_module_init_env &env);
    void initModule(std::shared_ptr<MachOModule> module);
    void setErrno(int no);
    void setErrnoAddr(uint64_t addr);
    
protected:
    ib_module_init_env defaultEnv;
    uint64_t errnoAddr;
    std::vector<ib_pendding_thread *> penddingThread;
    std::vector<ib_pendding_thread *> contextList;
};

NS_IB_END

#endif /* aarch64_machine_hpp */
