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

/*
 * operation bits [7, 0] contain the operation code.
 *
 * NOTE: make sure to add logic for handling any new
 *       types to kdp_ulock_find_owner()
 */
#define UL_COMPARE_AND_WAIT             1
#define UL_UNFAIR_LOCK                  2
#define UL_COMPARE_AND_WAIT_SHARED      3
#define UL_UNFAIR_LOCK64_SHARED         4
#define UL_COMPARE_AND_WAIT64           5
#define UL_COMPARE_AND_WAIT64_SHARED    6

/*
 * masks
 */
#define UL_OPCODE_MASK          0x000000FF
#define UL_FLAGS_MASK           0xFFFFFF00
#define ULF_GENERIC_MASK        0xFFFF0000

#define ULF_WAIT_MASK           (ULF_NO_ERRNO | \
                             ULF_WAIT_WORKQ_DATA_CONTENTION | \
                             ULF_WAIT_CANCEL_POINT | ULF_WAIT_ADAPTIVE_SPIN)

#define ULF_WAKE_MASK           (ULF_NO_ERRNO | \
                             ULF_WAKE_ALL | \
                             ULF_WAKE_THREAD | \
                             ULF_WAKE_ALLOW_NON_OWNER)

/*
 * operation bits [15, 8] contain the flags for __ulock_wake
 */
#define ULF_WAKE_ALL                    0x00000100
#define ULF_WAKE_THREAD                 0x00000200
#define ULF_WAKE_ALLOW_NON_OWNER        0x00000400

/*
 * operation bits [23, 16] contain the flags for __ulock_wait
 *
 * @const ULF_WAIT_WORKQ_DATA_CONTENTION
 * The waiter is contending on this lock for synchronization around global data.
 * This causes the workqueue subsystem to not create new threads to offset for
 * waiters on this lock.
 *
 * @const ULF_WAIT_CANCEL_POINT
 * This wait is a cancelation point
 *
 * @const ULF_WAIT_ADAPTIVE_SPIN
 * Use adaptive spinning when the thread that currently holds the unfair lock
 * is on core.
 */
#define ULF_WAIT_WORKQ_DATA_CONTENTION  0x00010000
#define ULF_WAIT_CANCEL_POINT           0x00020000
#define ULF_WAIT_ADAPTIVE_SPIN          0x00040000

/*
 * operation bits [31, 24] contain the generic flags
 */
#define ULF_NO_ERRNO                    0x01000000

NS_IB_BEGIN

class Aarch64Machine;

enum PthreadInternalState {
    PthreadInternalStateNew = 0,
    PthreadInternalStateRunning,
    PthreadInternalStateWaiting,
    PthreadInternalStateTerminated
};

typedef std::function<void (uc_engine *uc)> PthreadContinuation;

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
    PthreadContinuation continuation;
} PthreadInternal;

typedef enum {
    ULK_INVALID = 0,
    ULK_UADDR,
    ULK_XPROC,
} ib_ulk_type;

typedef struct {
    union {
        struct __attribute__((packed)) {
            user_addr_t     ulk_addr;
            pid_t           ulk_pid;
        };
        struct __attribute__((packed)) {
            uint64_t        ulk_object;
            uint64_t        ulk_offset;
        };
    };
    ib_ulk_type        ulk_key_type;
} ib_ulk_t;

typedef struct ib_ull {
    /*
     * ull_owner is the most recent known value for the owner of this ulock
     * i.e. it may be out of date WRT the real value in userspace.
     */
    mach_port_t     ull_owner; /* holds +1 thread reference */
    ib_ulk_t        ull_key;
//    ull_lock_t      ull_lock;
//    uint            ull_bucket_index;
    int32_t         ull_nwaiters;
    int32_t         ull_refcount;
    uint8_t         ull_opcode;
    std::vector<mach_port_t> waiters;
//    struct turnstile *ull_turnstile;
//    queue_chain_t   ull_hash_link;
} ib_ull_t;

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
    std::shared_ptr<PthreadInternal> findThreadByPort(mach_port_t port);
    
    std::shared_ptr<ib_ull> ull_get(ib_ulk_t &key, uint32_t flags);
    void yieldWithUll(std::shared_ptr<ib_ull> ull);
    void wakeupWithUll(std::shared_ptr<ib_ull> ull);
protected:
    std::map<mach_port_t, std::shared_ptr<PthreadInternal>> port2thread;
    std::vector<std::shared_ptr<PthreadInternal>> threads;
    std::shared_ptr<PthreadInternal> activeThread;
    bool enableInterrupt;
    
    // waitq
    std::map<std::pair<int, std::pair<uint64_t, uint64_t>>, std::shared_ptr<ib_ull>> ullBucket;
    std::vector<std::shared_ptr<PthreadInternal>> waitqThreads;
    
    std::pair<int, std::pair<uint64_t, uint64_t>> ull_hashindex(ib_ulk_t &key);
};

NS_IB_END

#endif /* pthread_kern_hpp */
