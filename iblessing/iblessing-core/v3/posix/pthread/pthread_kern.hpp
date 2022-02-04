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
#include <iblessing-core/core/polyfill/mach-universal.hpp>
#include <map>
#include <vector>
//#include <iblessing-core/v3/mach-o/macho-loader.hpp>
//#include <iblessing-core/v3/kernel/syscall/aarch64-svc-manager.hpp>

// update flags
/*
 * Flags filed passed to bsdthread_create and back in pthread_start
 * 31  <---------------------------------> 0
 * _________________________________________
 * | flags(8) | policy(8) | importance(16) |
 * -----------------------------------------
 */
#define PTHREAD_START_CUSTOM        0x01000000 // <rdar://problem/34501401>
#define PTHREAD_START_SETSCHED        0x02000000
// was PTHREAD_START_DETACHED        0x04000000
#define PTHREAD_START_QOSCLASS        0x08000000
#define PTHREAD_START_TSD_BASE_SET    0x10000000
#define PTHREAD_START_SUSPENDED        0x20000000
#define PTHREAD_START_QOSCLASS_MASK 0x00ffffff
#define PTHREAD_START_POLICY_BITSHIFT 16
#define PTHREAD_START_POLICY_MASK 0xff
#define PTHREAD_START_IMPORTANCE_MASK 0xffff

/* flag values for upcall flags field, only 8 bits per struct threadlist */
#define WQ_FLAG_THREAD_PRIO_SCHED               0x00008000
#define WQ_FLAG_THREAD_PRIO_QOS                 0x00004000
#define WQ_FLAG_THREAD_PRIO_MASK                0x00000fff

#define WQ_FLAG_THREAD_OVERCOMMIT               0x00010000  /* thread is with overcommit prio */
#define WQ_FLAG_THREAD_REUSE                    0x00020000  /* thread is being reused */
#define WQ_FLAG_THREAD_NEWSPI                   0x00040000  /* the call is with new SPIs */
#define WQ_FLAG_THREAD_KEVENT                   0x00080000  /* thread is response to kevent req */
#define WQ_FLAG_THREAD_EVENT_MANAGER            0x00100000  /* event manager thread */
#define WQ_FLAG_THREAD_TSD_BASE_SET             0x00200000  /* tsd base has already been set */
#define WQ_FLAG_THREAD_WORKLOOP                 0x00400000  /* workloop thread */
#define WQ_FLAG_THREAD_OUTSIDEQOS               0x00800000  /* thread qos changes should not be sent to kernel */

/*
 * Workloop
 */
#define DISPATCH_WLH_ANON       ((void*)(~0x3ul))
#define DISPATCH_WLH_MANAGER    ((void*)(~0x7ul))


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

/* SPI flags between WQ and workq_setup_thread in pthread.kext */
#define WQ_SETUP_NONE           0
#define WQ_SETUP_FIRST_USE      1
#define WQ_SETUP_CLEAR_VOUCHER  2
// was  WQ_SETUP_SET_SCHED_CALL 4
#define WQ_SETUP_EXIT_THREAD    8

/* workq_kernreturn commands */
#define WQOPS_THREAD_RETURN              0x004 /* parks the thread back into the kernel */
#define WQOPS_QUEUE_NEWSPISUPP           0x010 /* this is to check for newer SPI support */
#define WQOPS_QUEUE_REQTHREADS           0x020 /* request number of threads of a prio */
#define WQOPS_QUEUE_REQTHREADS2          0x030 /* request a number of threads in a given priority bucket */
#define WQOPS_THREAD_KEVENT_RETURN       0x040 /* parks the thread after delivering the passed kevent array */
#define WQOPS_SET_EVENT_MANAGER_PRIORITY 0x080 /* max() in the provided priority in the the priority of the event manager */
#define WQOPS_THREAD_WORKLOOP_RETURN     0x100 /* parks the thread after delivering the passed kevent array */
#define WQOPS_SHOULD_NARROW              0x200 /* checks whether we should narrow our concurrency */
#define WQOPS_SETUP_DISPATCH             0x400 /* setup pthread workqueue-related operations */

#define WORKQ_DISPATCH_CONFIG_VERSION        2
#define WORKQ_DISPATCH_MIN_SUPPORTED_VERSION 1
#define WORKQ_DISPATCH_SUPPORTED_FLAGS       0
struct workq_dispatch_config {
    uint32_t wdc_version;
    uint32_t wdc_flags;
    uint64_t wdc_queue_serialno_offs;
    uint64_t wdc_queue_label_offs;
} __attribute__((packed, aligned(4)));

typedef void *thread_call_param_t;
typedef void (*thread_call_func_t)(
    thread_call_param_t     param0,
    thread_call_param_t     param1);

struct thread_call {
    thread_call_func_t      tc_func;
    thread_call_param_t     tc_param0;
    thread_call_param_t     tc_param1;
};

typedef struct thread_call *thread_call_t;

enum workq_state_flags_t {
    WQ_EXITING                  = 0x0001,
    WQ_PROC_SUSPENDED           = 0x0002,
    WQ_DEATH_CALL_SCHEDULED     = 0x0004,

    WQ_DELAYED_CALL_SCHEDULED   = 0x0010,
    WQ_DELAYED_CALL_PENDED      = 0x0020,
    WQ_IMMEDIATE_CALL_SCHEDULED = 0x0040,
    WQ_IMMEDIATE_CALL_PENDED    = 0x0080,
};

struct uthread {
    
};

struct workqueue {
    uint32_t wq_event_manager_priority;
    thread_call_t   wq_delayed_call;
    thread_call_t   wq_immediate_call;
    thread_call_t   wq_death_call;
    workq_state_flags_t wq_flags;
    struct uthread *wq_creator;
    
    uint16_t        wq_nthreads;
    uint16_t        wq_thidlecount;
};

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
    uint32_t flags;
    
    // context
    uc_context *ctx;
    
    // props
    mach_port_t thread_port;
    PthreadInternalState state;
    bool isMain;
    int ticks;
    int maxTikcs;
    std::string name;
    bool discardCurrentContext;
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
    uint64_t p_dispatchqueue_serialno_offset;
    uint64_t p_dispatchqueue_label_offset;
    std::shared_ptr<struct workqueue> workq;
    std::weak_ptr<Aarch64Machine> machine;
    
    void createThread(std::shared_ptr<PthreadInternal> s);
    void terminateThread(mach_port_t port);
    bool tick();
    void setInterruptEnable(bool enable);
    bool getInterruptEnableState();
    void setActiveThread(std::shared_ptr<PthreadInternal> s);
    void contextSwitch(std::shared_ptr<PthreadInternal> nextThread = nullptr, bool forceSwitch = false);
    std::shared_ptr<PthreadInternal> currentThread();
    std::shared_ptr<PthreadInternal> findThreadByPort(mach_port_t port);
    
    std::shared_ptr<ib_ull> ull_get(ib_ulk_t &key, uint32_t flags);
    void yieldWithUll(std::shared_ptr<ib_ull> ull);
    void wakeupWithUll(std::shared_ptr<ib_ull> ull);
    
    // workloop
    void pendingWorkloopForMach(ib_mach_msg_header_t *msgbuf);
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
