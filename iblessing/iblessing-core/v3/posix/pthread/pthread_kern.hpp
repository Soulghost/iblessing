//
//  pthread_kern.hpp
//  pthread_kern
//
//  Created by Soulghost on 2022/1/8.
//  Copyright © 2022 soulghost. All rights reserved.
//

#ifndef pthread_kern_hpp
#define pthread_kern_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <map>
#include <vector>
//#include <iblessing-core/v3/mach-o/macho-loader.hpp>
//#include <iblessing-core/v3/kernel/syscall/aarch64-svc-manager.hpp>

NS_IB_BEGIN

class Aarch64Machine;

enum PthreadInternalState {
    PthreadInternalStateNew = 0,
    PthreadInternalStateRunning,
    PthreadInternalStateWaiting,
    PthreadInternalStateTerminated
};

typedef struct PthreadInternal {
    // init state
    uint64_t x[8];
    uint64_t sp;
    uint64_t pc;
    uint64_t self;
    uint64_t tsd;
    
    // context
    uc_context *ctx;
    
    // props
    mach_port_t thread_port;
    PthreadInternalState state;
    bool isMain;
    int ticks;
    int maxTikcs;
    std::string name;
} PthreadInternal;

class PthreadKern {
public:
    uint64_t proc_threadstart;
    uint64_t proc_wqthread;
    std::weak_ptr<Aarch64Machine> machine;
    
    void createThread(std::shared_ptr<PthreadInternal> s);
    void terminateThread(mach_port_t port);
    bool tick();
    void setInterruptEnable(bool enable);
    bool getInterruptEnableState();
    void setActiveThread(std::shared_ptr<PthreadInternal> s);
    void contextSwitch(std::shared_ptr<PthreadInternal> nextThread = nullptr);
    std::shared_ptr<PthreadInternal> currentThread();
protected:
    std::map<mach_port_t, std::shared_ptr<PthreadInternal>> port2thread;
    std::vector<std::shared_ptr<PthreadInternal>> threads;
    std::shared_ptr<PthreadInternal> activeThread;
    bool enableInterrupt;
};

NS_IB_END

#endif /* pthread_kern_hpp */
