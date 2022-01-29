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

void PthreadKern::contextSwitch(shared_ptr<PthreadInternal> nextThread, bool forceSwitch) {
    // thread termination can be interrupted
    BufferedLogger *logger = BufferedLogger::globalLogger();
    if (!forceSwitch) {
        assert(enableInterrupt == true || currentThread() == nullptr);
    }
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
        if (!activeThread->discardCurrentContext) {
            // save the context for the current thread
            if (!activeThread->ctx) {
                assert(uc_context_alloc(uc, &activeThread->ctx) == UC_ERR_OK);
            }
            assert(uc_context_save(uc, activeThread->ctx) == UC_ERR_OK);
            activeThread->state = PthreadInternalStateWaiting;
        } else {
            activeThread->discardCurrentContext = false;
//            assert(activeThread->ctx != NULL);
            assert(activeThread->state == PthreadInternalStateNew);
            printf("[Stalker][+][Thread] discard current context for thread %s, maybe a workqueue bootstrap thread to workthread\n", activeThread->name.c_str());
            logger->append(StringUtils::format("[Stalker][+][Thread] discard current context for thread %s, maybe a workqueue bootstrap thread to workthread\n", activeThread->name.c_str()));
        }
    }
    
    uint64_t pc, sp, lr, tsd;
    ensure_uc_reg_read(UC_ARM64_REG_PC, &pc);
    ensure_uc_reg_read(UC_ARM64_REG_SP, &sp);
    ensure_uc_reg_read(UC_ARM64_REG_LR, &lr);
    ensure_uc_reg_read(UC_ARM64_REG_TPIDRRO_EL0, &tsd);
    string beforeContent = StringUtils::format("[Stalker][+][Thread] before switch %s -> %s: pc 0x%llx, sp 0x%llx, lr 0x%llx, tsd 0x%llx, state %s\n", activeThread ? activeThread->name.c_str() : "terminated", pendingThread->name.c_str(), pc, sp, lr, tsd, uc_get_thread_state_desc(uc).c_str());
    printf("%s", beforeContent.c_str());
    logger->append(beforeContent);
    
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
        string afterContent = StringUtils::format("[Stalker][+][Thread] after switch %s -> %s(new create): pc 0x%llx, sp 0x%llx tsd 0x%llx, state %s\n", activeThread ? activeThread->name.c_str() : "terminated", pendingThread->name.c_str(), pendingThread->pc, pendingThread->sp, pendingThread->tsd, uc_get_thread_state_desc(uc).c_str());
        printf("%s", afterContent.c_str());
        logger->append(afterContent);
    } else {
        // restore thread state
        assert(pendingThread->ctx != NULL);
        assert(uc_context_restore(uc, pendingThread->ctx) == UC_ERR_OK);
        // notify unicorn
        uint64_t pc, sp, tsd;
        ensure_uc_reg_read(UC_ARM64_REG_PC, &pc);
        ensure_uc_reg_write(UC_ARM64_REG_PC, &pc);
        ensure_uc_reg_read(UC_ARM64_REG_SP, &sp);
        ensure_uc_reg_read(UC_ARM64_REG_TPIDRRO_EL0, &tsd);
        string afterContent = StringUtils::format("[Stalker][+][Thread] after switch %s -> %s(wakeup): pc 0x%llx, sp 0x%llx, tsd 0x%llx, state %s\n", activeThread ? activeThread->name.c_str() : "terminated", pendingThread->name.c_str(), pc, sp, tsd, uc_get_thread_state_desc(uc).c_str());
        printf("%s", afterContent.c_str());
        logger->append(afterContent);
        
        if (pendingThread->continuation) {
            printf("[Stalker][+][Thread] execute continuation for thread %s\n", pendingThread->name.c_str());
            logger->append(StringUtils::format("[Stalker][+][Thread] execute continuation for thread %s\n", pendingThread->name.c_str()));
            pendingThread->continuation(uc);
            pendingThread->continuation = NULL;
        }
    }
    // change thread state
    activeThread = pendingThread;
    activeThread->state = PthreadInternalStateRunning;
    activeThread->ticks = 0;
    activeThread->maxTikcs = activeThread->maxTikcs ?: 30;
//    printf("[Stalker][+][Thread] switch to thread %s\n", activeThread->name.c_str());
}

shared_ptr<PthreadInternal> PthreadKern::currentThread() {
    return activeThread;
}

shared_ptr<PthreadInternal> PthreadKern::findThreadByPort(mach_port_t port) {
    if (port2thread.find(port) != port2thread.end()) {
        return port2thread[port];
    }
    return nullptr;
}

void PthreadKern::setInterruptEnable(bool enable) {
    this->enableInterrupt = enable;
}

bool PthreadKern::getInterruptEnableState() {
    return this->enableInterrupt;
}

shared_ptr<ib_ull> PthreadKern::ull_get(ib_ulk_t &key, uint32_t flags) {
    auto index = ull_hashindex(key);
    if (ullBucket.find(index) != ullBucket.end()) {
        return ullBucket[index];
    }
    shared_ptr<ib_ull> ull = make_shared<ib_ull>();
    ull->ull_key = key;
    ull->ull_refcount = 1;
    ull->ull_key = key;
    ull->ull_nwaiters = 0;
    ull->ull_opcode = 0;
    ull->ull_owner = THREAD_NULL;
    ullBucket[index] = ull;
    return ull;
}

pair<int, pair<uint64_t, uint64_t>> PthreadKern::ull_hashindex(ib_ulk_t &key) {
    return {key.ulk_key_type, {key.ulk_addr, key.ulk_pid}};
}

void PthreadKern::yieldWithUll(shared_ptr<ib_ull> ull) {
    enableInterrupt = true;
    mach_port_t target_port = ull->ull_owner;
    shared_ptr<PthreadInternal> targetThread = findThreadByPort(target_port);
    assert(targetThread != nullptr);
    
    auto currentIt = find(threads.begin(), threads.end(), activeThread);
    assert(currentIt != threads.end());
    activeThread->continuation = [](uc_engine *uc) {
        syscall_return_value(0);
    };
    threads.erase(currentIt);
    waitqThreads.push_back(activeThread);
    contextSwitch(targetThread);
}

void PthreadKern::wakeupWithUll(shared_ptr<ib_ull> ull) {
    for (mach_port_t waiter_port : ull->waiters) {
        shared_ptr<PthreadInternal> waiterThread = findThreadByPort(waiter_port);
        assert(waiterThread != nullptr);
        assert(find(threads.begin(), threads.end(), waiterThread) == threads.end());
        threads.push_back(waiterThread);
        
        auto waiterIt = find(waitqThreads.begin(), waitqThreads.end(), waiterThread);
        assert(waiterIt != waitqThreads.end());
        waitqThreads.erase(waiterIt);
    }
}
