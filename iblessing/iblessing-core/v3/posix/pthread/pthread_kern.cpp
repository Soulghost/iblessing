//
//  pthread_kern.cpp
//  pthread_kern
//
//  Created by Soulghost on 2022/1/8.
//  Copyright © 2022 soulghost. All rights reserved.
//

#include "pthread_kern.hpp"
#include "aarch64-machine.hpp"
#include "buffered_logger.hpp"
#include "uc_debugger_utils.hpp"
#include "StringUtils.h"
#include <mach/mach_init.h>
#include <mach/mach_port.h>

using namespace std;
using namespace iblessing;

static int threadCounter = 1;

void PthreadKern::createThread(shared_ptr<PthreadInternal> s) {
    assert(port2thread.find(s->thread_port) == port2thread.end());
    if (s->name.length() == 0) {
        s->name = StringUtils::format("unamed-thread-%d", threadCounter++);
    }
    port2thread[s->thread_port] = s;
    threads.push_back(s);
    printf("[Stalker][+][Thread] create thread %s\n", s->name.c_str());
}

void PthreadKern::terminateThread(mach_port_t port) {
    assert(port2thread.find(port) != port2thread.end());
    shared_ptr<PthreadInternal> s = port2thread[port];
    auto it = threads.begin();
    for (; it != threads.end(); it++) {
        if (*it == s) {
            it = threads.erase(it);
            break;
        }
    }
    port2thread.erase(port);
    printf("[Stalker][+][Thread] thread %s terminated\n", s->name.c_str());
    
    activeThread = nullptr;
    if (it != threads.end()) {
        contextSwitch(*it);
    } else {
        contextSwitch();
    }
}

void PthreadKern::setActiveThread(shared_ptr<PthreadInternal> s) {
    activeThread = s;
    activeThread->state = PthreadInternalStateRunning;
}

bool PthreadKern::tick() {
    if (!enableInterrupt) {
        return false;
    }
    
    if (threads.size() == 1) {
        // only main thread
        return false;
    }
    
    activeThread->ticks += 1;
    if (activeThread->ticks >= activeThread->maxTikcs) {
        activeThread->ticks = 0;
        contextSwitch();
        return true;
    }
    return false;
}

void PthreadKern::contextSwitch(shared_ptr<PthreadInternal> nextThread) {
    // thread termination can be interrupted
    assert(enableInterrupt == true || currentThread() == nullptr);
    shared_ptr<PthreadInternal> pendingThread;
    if (__builtin_expect(nextThread == nullptr, true)) {
        auto it = threads.begin();
        for (; it != threads.end(); it++) {
            if (*it == activeThread) {
                it++;
                break;
            }
        }
        if (it == threads.end()) {
            it = threads.begin();
        }
        pendingThread = *it;
    } else {
        pendingThread = nextThread;
    }
    assert(pendingThread != activeThread);
    
    shared_ptr<Aarch64Machine> m = machine.lock();
    uc_engine *uc = m->uc;
    if (activeThread) {
        // save the context for the current thread
        if (!activeThread->ctx) {
            assert(uc_context_alloc(uc, &activeThread->ctx) == UC_ERR_OK);
        }
        assert(uc_context_save(uc, activeThread->ctx) == UC_ERR_OK);
        activeThread->state = PthreadInternalStateWaiting;
    }
    
    uint64_t pc, lr, tsd, x16;
    ensure_uc_reg_read(UC_ARM64_REG_PC, &pc);
    ensure_uc_reg_read(UC_ARM64_REG_LR, &lr);
    ensure_uc_reg_read(UC_ARM64_REG_TPIDRRO_EL0, &tsd);
    ensure_uc_reg_read(UC_ARM64_REG_X16, &x16);
    printf("[Stalker][+][Thread] before switch %s -> %s: pc 0x%llx, lr 0x%llx, tsd 0x%llx, x16 0x%llx\n", activeThread ? activeThread->name.c_str() : "terminated", pendingThread->name.c_str(), pc, lr, tsd, x16);
    
    if (pendingThread->state == PthreadInternalStateNew) {
        // thread start
        ensure_uc_reg_write(UC_ARM64_REG_TPIDRRO_EL0, &pendingThread->tsd);
        ensure_uc_reg_write(UC_ARM64_REG_SP, &pendingThread->sp);
        for (int i = 0; i < 8; i++) {
            ensure_uc_reg_write(UC_ARM64_REG_X0 + i, &pendingThread->x[i]);
        }
        uint64_t threadShouldNeverReturnLR = 0xfafafafa;
        ensure_uc_reg_write(UC_ARM64_REG_LR, &threadShouldNeverReturnLR);
        ensure_uc_reg_write(UC_ARM64_REG_PC, &pendingThread->pc);
    } else {
        // restore thread state
        assert(pendingThread->ctx != NULL);
        assert(uc_context_restore(uc, pendingThread->ctx) == UC_ERR_OK);
        // notify unicorn
        uint64_t pc, tsd, x16;
        ensure_uc_reg_read(UC_ARM64_REG_PC, &pc);
        ensure_uc_reg_write(UC_ARM64_REG_PC, &pc);
        ensure_uc_reg_read(UC_ARM64_REG_X16, &x16);
        ensure_uc_reg_read(UC_ARM64_REG_TPIDRRO_EL0, &tsd);
        printf("[Stalker][+][Thread] after switch %s -> %s: pc 0x%llx, tsd 0x%llx, x16 0x%llx\n", activeThread ? activeThread->name.c_str() : "terminated", pendingThread->name.c_str(), pc, tsd, x16);
    }
    // change thread state
    activeThread = pendingThread;
    activeThread->state = PthreadInternalStateRunning;
    activeThread->ticks = 0;
    activeThread->maxTikcs = 30;
//    printf("[Stalker][+][Thread] switch to thread %s\n", activeThread->name.c_str());
}

shared_ptr<PthreadInternal> PthreadKern::currentThread() {
    return activeThread;
}

void PthreadKern::setInterruptEnable(bool enable) {
    this->enableInterrupt = enable;
}

bool PthreadKern::getInterruptEnableState() {
    return this->enableInterrupt;
}
