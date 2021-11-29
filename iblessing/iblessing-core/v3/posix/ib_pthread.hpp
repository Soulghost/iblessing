//
//  ib_pthread.hpp
//  ib_pthread
//
//  Created by Soulghost on 2021/9/27.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef ib_pthread_hpp
#define ib_pthread_hpp

#include <unistd.h>

typedef struct ib_SchedParam {
    int sched_priority;
    int pad;
} ib_SchedParam;

typedef struct ib_TailqPthread {
    uint64_t tqe_next;
    uint64_t tqe_prev;
} ib_TailqPthread;

typedef struct ib_pthread {
    long sig; // _PTHREAD_SIG
    uint64_t __cleanup_stack;
    int childrun;
    int lock;
    int detached;
    int pad0;
    uint64_t thread_id; // 64-bit unique thread id
    uint64_t fun; // thread start routine
    uint64_t arg; // thread start routine argument
    uint64_t exit_value; // thread exit value storage
    uint64_t joiner_notify; // pthread_join notification
    int max_tsd_key;
    int cancel_state; // whether the thread can be cancelled
    int cancel_error;
    int err_no; // thread-local errno
    uint64_t joiner;
    ib_SchedParam param;
    ib_TailqPthread plist; // global thread list
    char pthread_name[64];

    uint64_t stackaddr; // base of the stack
    uint64_t stacksize; // size of stack (page multiple and >= PTHREAD_STACK_MIN)

    uint64_t freeaddr; // stack/thread allocation base address
    uint64_t freesize; // stack/thread allocation size
    uint64_t guardsize; // guard page size in bytes
    
    uint64_t self;
    uint64_t errno_;
    uint64_t mig_reply;
    uint64_t machThreadSelf;
    uint64_t padding;
    uint64_t p1;
    uint64_t p2;
    uint32_t munge_token;
    uint32_t p3;
} ib_pthread;

#endif /* ib_pthread_hpp */
