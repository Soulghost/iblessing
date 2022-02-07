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
#include "libdispatch_defines.hpp"
#include "pthread_types_14.h"
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>

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
    activeThread->maxTikcs = activeThread->maxTikcs ?: 200;
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

void PthreadKern::createWorkerThreadsIfNeeded() {
    shared_ptr<struct workqueue> wq = workq;
    assert(wq != nullptr);
    
    struct uthread *uth = wq->wq_creator;
    assert(wq->wq_thidlecount == 0);
    assert(uth == nullptr);
    
    // try dispatch the first workq thread
    bool overcommit = false;
    for (int i = 0; i < 2; i++) {
        uint64_t th_stacksize = 1024 * 1024; // 0x100000
        uint64_t th_stackaddr = machine.lock()->loader->memoryManager->alloc(th_stacksize);
        // realstack
        uint64_t stacktop_addr = th_stackaddr + 0x87000;
        // try to dispatch the thread
        // update port
        mach_port_t threadPort = 0;
        assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &threadPort) == KERN_SUCCESS);
        
        uint32_t upcall_flags = 0;
        // default queue
        upcall_flags |= WQ_FLAG_THREAD_TSD_BASE_SET;
        upcall_flags |= WQ_FLAG_THREAD_PRIO_SCHED;
        upcall_flags |= WQ_FLAG_THREAD_PRIO_QOS;
        upcall_flags |= 4; // 0x80 << 4 => 0x8 00 (1000B)
        if (overcommit) {
            upcall_flags |= (1 << 16);
        }

        // get tsd
        ib_pthread_s *pthread = (ib_pthread_s *)th_stackaddr;
        uint64_t pthreadTSD = th_stackaddr + __offsetof(ib_pthread_s, tsd);
        *((uint64_t *)pthreadTSD + 3) = threadPort;

        // init state
        shared_ptr<PthreadKern> threadManager = machine.lock()->threadManager;
        shared_ptr<PthreadInternal> s = make_shared<PthreadInternal>();
        s->x[0] = (uint64_t)pthread; // pthread_self
        s->x[1] = threadPort; // kport
        s->x[2] = th_stackaddr; // stacklowaddr
        s->x[3] = 0; // keventlist
        s->x[4] = upcall_flags; // upcall_flags
        s->x[5] = 0; // kevent_count
        s->x[6] = 0;
        s->x[7] = 0;
        s->sp = stacktop_addr;
        s->pc = threadManager->proc_wqthread;
        s->thread_port = threadPort;
        s->state = PthreadInternalStateNew;
        s->self = th_stackaddr;
        s->tsd = pthreadTSD;
        s->isMain = false;
        s->ctx = NULL;
        s->ticks = 0;
        s->maxTikcs = 500;
        s->name = StringUtils::format("kernel_wqthread_default_qos%s", overcommit ? "_overcommit" : "");
        s->once = false;
        machine.lock()->threadManager->createThread(s);
        if (!overcommit) {
            overcommit = true;
        }
    }
}

void PthreadKern::initDispatchQueues() {
    dispatch_queue_global_s *rootQueues = (dispatch_queue_global_s *)0x9D289CFC0;
    for (int i = 0; i < 12; i++) {
        printf("[Stalker][*][Dispatch] root queue #%d: %p, name %s\n", i, rootQueues, rootQueues->dq_label);
        shared_ptr<ib_dispatch_queue_item> item = make_shared<ib_dispatch_queue_item>();
        item->queue_in_libdispatch = (void *)rootQueues;
        label2dispatch_queues[rootQueues->dq_label] = item;
        rootQueues += 1;
    }
}

void PthreadKern::pendingWorkloopForMach(ib_mach_msg_header_t *msgbuf, ib_mach_port_t recv_port, uint64_t unote, uint64_t kqueue_id, int kr) {
    // create workloop thread
    bool overcommit = true;
    uint64_t th_stacksize = 1024 * 1024; // 0x100000
    uint64_t th_stackaddr = machine.lock()->loader->memoryManager->alloc(th_stacksize);
    // realstack
    uint64_t stacktop_addr = th_stackaddr + 0x87000;
    // try to dispatch the thread
    // update port
    mach_port_t threadPort = 0;
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &threadPort) == KERN_SUCCESS);
    
    uint32_t upcall_flags = 0;
    // default queue
    upcall_flags |= WQ_FLAG_THREAD_TSD_BASE_SET;
    {
        upcall_flags |= WQ_FLAG_THREAD_WORKLOOP;
//        upcall_flags |= WQ_FLAG_THREAD_KEVENT;
    }
    upcall_flags |= WQ_FLAG_THREAD_PRIO_SCHED;
    upcall_flags |= WQ_FLAG_THREAD_PRIO_QOS;
    upcall_flags |= 4; // 0x80 << 4 => 0x8 00 (1000B)
    upcall_flags |= (1 << 16); // overcommit

    // get tsd
    ib_pthread_s *pthread = (ib_pthread_s *)th_stackaddr;
    uint64_t pthreadTSD = th_stackaddr + __offsetof(ib_pthread_s, tsd);
    *((uint64_t *)pthreadTSD + 3) = threadPort;

    shared_ptr<PthreadKern> threadManager = machine.lock()->threadManager;
    uint64_t keventlist_head_addr = machine.lock()->loader->memoryManager->alloc(0x10000);
    
//    auto queueItem = label2dispatch_queues.find("com.apple.root.default-qos.overcommit");
//    assert(queueItem != label2dispatch_queues.end());
    uc_engine *uc = machine.lock()->uc;
    ensure_uc_mem_write(keventlist_head_addr, &kqueue_id, sizeof(uint64_t));
    uint64_t keventlist_addr = keventlist_head_addr + 8;
    
    int kevent_count = 1;
    
    // mach event
    kevent_qos_s *e0 = (kevent_qos_s *)keventlist_addr;
    e0->ident = recv_port;
    e0->filter = EVFILT_MACHPORT;
    e0->flags = 0x0185;
    e0->qos = 0x800010ff;
    e0->udata = unote; // _dispatch_unote_create_without_handle in dispatch_source_type(mach_recv (channel))
    e0->fflags = kr; // mach_error
    e0->data = 0;
    e0->ext[0] = (uint64_t)msgbuf; // mach_msg_header_t (msgbuf)
    e0->ext[1] = msgbuf->msgh_size; // mach_msg_size
    e0->ext[2] = 0x000010ff000010ff; // msg priority
    e0->ext[3] = 0;
    
    // init state
    shared_ptr<PthreadInternal> s = make_shared<PthreadInternal>();
    s->x[0] = (uint64_t)pthread; // pthread_self
    s->x[1] = threadPort; // kport
    s->x[2] = th_stackaddr; // stacklowaddr
    s->x[3] = keventlist_addr; // keventlist
    s->x[4] = upcall_flags; // upcall_flags
    s->x[5] = kevent_count; // kevent_count
    s->x[6] = 0;
    s->x[7] = 0;
    s->sp = stacktop_addr;
    s->pc = threadManager->proc_wqthread;
    s->thread_port = threadPort;
    s->state = PthreadInternalStateNew;
    s->self = th_stackaddr;
    s->tsd = pthreadTSD;
    s->isMain = false;
    s->ctx = NULL;
    s->ticks = 0;
    s->maxTikcs = 500;
    s->name = StringUtils::format("kernel_workloop_xpc_mach_callback_default_qos%s", overcommit ? "_overcommit" : "");
    s->once = true;
    machine.lock()->threadManager->createThread(s);
}

void PthreadKern::createPendingWorkloopEvent() {
    bool overcommit = true;
    uint64_t th_stacksize = 1024 * 1024; // 0x100000
    uint64_t th_stackaddr = machine.lock()->loader->memoryManager->alloc(th_stacksize);
    // realstack
    uint64_t stacktop_addr = th_stackaddr + 0x87000;
    // try to dispatch the thread
    // update port
    mach_port_t threadPort = 0;
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &threadPort) == KERN_SUCCESS);
    
    uint32_t upcall_flags = 0;
    // default queue
    upcall_flags |= WQ_FLAG_THREAD_TSD_BASE_SET;
    upcall_flags |= WQ_FLAG_THREAD_WORKLOOP;
    upcall_flags |= WQ_FLAG_THREAD_PRIO_SCHED;
    upcall_flags |= WQ_FLAG_THREAD_PRIO_QOS;
    upcall_flags |= 4; // 0x80 << 4 => 0x8 00 (1000B)
    upcall_flags |= (1 << 16); // overcommit

    // get tsd
    ib_pthread_s *pthread = (ib_pthread_s *)th_stackaddr;
    uint64_t pthreadTSD = th_stackaddr + __offsetof(ib_pthread_s, tsd);
    *((uint64_t *)pthreadTSD + 3) = threadPort;

    uint64_t keventlist_head_addr = machine.lock()->loader->memoryManager->alloc(0x10000);
    
    auto queueItem = label2dispatch_queues.find("com.apple.root.default-qos.overcommit");
    assert(queueItem != label2dispatch_queues.end());
    uint64_t queue_addr = (uint64_t)queueItem->second->queue_in_libdispatch;
    
    uc_engine *uc = machine.lock()->uc;
    ensure_uc_mem_write(keventlist_head_addr, &queue_addr, sizeof(uint64_t));
    uint64_t keventlist_addr = keventlist_head_addr + 8;
    
    int kevent_count = 1;
    kevent_qos_s *e0 = (kevent_qos_s *)keventlist_addr;
    e0->ident = queue_addr;
    e0->filter = EVFILT_WORKLOOP;
    e0->flags = 37;
    e0->qos = 0x800008ff;
    e0->udata = queue_addr;
    e0->xflags = 0;
    e0->data = 0;
    e0->ext[0] = 0;
    e0->ext[1] = 233;
    
    // init state
    shared_ptr<PthreadKern> threadManager = machine.lock()->threadManager;
    shared_ptr<PthreadInternal> s = make_shared<PthreadInternal>();
    s->x[0] = (uint64_t)pthread; // pthread_self
    s->x[1] = threadPort; // kport
    s->x[2] = th_stackaddr; // stacklowaddr
    s->x[3] = keventlist_addr; // keventlist
    s->x[4] = upcall_flags; // upcall_flags
    s->x[5] = kevent_count; // kevent_count
    s->x[6] = 0;
    s->x[7] = 0;
    s->sp = stacktop_addr;
    s->pc = threadManager->proc_wqthread;
    s->thread_port = threadPort;
    s->state = PthreadInternalStateNew;
    s->self = th_stackaddr;
    s->tsd = pthreadTSD;
    s->isMain = false;
    s->ctx = NULL;
    s->ticks = 0;
    s->maxTikcs = 500;
    s->name = StringUtils::format("kernel_workloop_event_default_qos%s", overcommit ? "_overcommit" : "");
    s->once = true;
    machine.lock()->threadManager->createThread(s);
}


void* pthread_port_worker(void *_ctx) {
    uint64_t *ctx = (uint64_t *)_ctx;
    mach_port_t port = (mach_port_t)ctx[0];
    mach_msg_header_t *msgbuf = (mach_msg_header_t *)ctx[1];
    PthreadKern *threadManager = (PthreadKern *)ctx[2];
    uint64_t unote = ctx[3];
    uint64_t kqueue_id = ctx[4];
    printf("[XPC] wait for port %d(0x%x)\n", port, port);
    
    
    msgbuf->msgh_size = 0x4000;
    msgbuf->msgh_local_port = port;
    kern_return_t kr = mach_msg_receive(msgbuf);
    printf("[XPC] msg received for port %d(0x%x), kr 0x%x(%s)\n", port, port, kr, mach_error_string(kr));
    
    
    
    shared_ptr<Aarch64Machine> machine = threadManager->machine.lock();
    ib_mach_msg_header_t *replybuf = (ib_mach_msg_header_t *)machine->loader->memoryManager->alloc(msgbuf->msgh_size);
    uc_engine *uc = machine->uc;
    ensure_uc_mem_write((uint64_t)replybuf, msgbuf, msgbuf->msgh_size);
    threadManager->pendingWorkloopForMach((ib_mach_msg_header_t *)replybuf, port, unote, kqueue_id, kr);
    
    free(ctx);
    return NULL;
}

void PthreadKern::wait4port_recv(ib_mach_port_t port, ib_mach_msg_header_t *msgbuf, uint64_t unote, uint64_t kqueue_id) {
    pthread_t s;
    uint64_t *ctx = (uint64_t *)malloc(8 * 3);
    ctx[0] = port;
    ctx[1] = (uint64_t)msgbuf;
    ctx[2] = (uint64_t)this;
    ctx[3] = unote;
    ctx[4] = kqueue_id;
    assert(pthread_create(&s, NULL, &pthread_port_worker, ctx) == 0);
}
