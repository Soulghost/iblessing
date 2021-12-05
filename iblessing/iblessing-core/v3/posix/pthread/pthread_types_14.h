//
//  pthread_types_14.h
//  pthread_types_14
//
//  Created by Soulghost on 2021/12/4.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef pthread_types_14_h
#define pthread_types_14_h

#include <unistd.h>
#include <iblessing-core/core/polyfill/mach-universal.hpp>

#define TRACEBUF

#define MAXTHREADNAMESIZE               64
#define __SCHED_PARAM_SIZE__       4
#define _EXTERNAL_POSIX_THREAD_KEYS_MAX 256
#define _INTERNAL_POSIX_THREAD_KEYS_MAX 256
#define _INTERNAL_POSIX_THREAD_KEYS_END 512
typedef int                    ib_errno_t;

#if defined(__clang__) && defined(__cplusplus)
#define __MISMATCH_TAGS_PUSH                                            \
    _Pragma("clang diagnostic push")                                \
    _Pragma("clang diagnostic ignored \"-Wmismatched-tags\"")
#define __MISMATCH_TAGS_POP                                             \
    _Pragma("clang diagnostic pop")
#else
#define __MISMATCH_TAGS_PUSH
#define __MISMATCH_TAGS_POP
#endif

#if defined(__clang__)
#define __NULLABILITY_COMPLETENESS_PUSH \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wnullability-completeness\"")
#define __NULLABILITY_COMPLETENESS_POP \
    _Pragma("clang diagnostic pop")
#else
#define __NULLABILITY_COMPLETENESS_PUSH
#define __NULLABILITY_COMPLETENESS_POP
#endif

#define TAILQ_ENTRY(type)                                               \
__MISMATCH_TAGS_PUSH                                                    \
__NULLABILITY_COMPLETENESS_PUSH                                         \
struct {                                                                \
    struct type *tqe_next;  /* next element */                      \
    struct type **tqe_prev; /* address of previous next element */  \
    TRACEBUF                                                        \
}                                                                       \
__NULLABILITY_COMPLETENESS_POP                                          \
__MISMATCH_TAGS_POP

struct ib__darwin_pthread_handler_rec {
    void (*__routine)(void *);    // Routine to call
    void *__arg;            // Argument to pass
    struct ib__darwin_pthread_handler_rec *__next;
};

struct ib_sched_param {
    int sched_priority;
    char __opaque[__SCHED_PARAM_SIZE__];
};

typedef struct ib_os_unfair_lock_s {
    uint32_t _os_unfair_lock_opaque;
} ib_os_unfair_lock, *ib_os_unfair_lock_t;

typedef ib_os_unfair_lock ib_pthread_lock;

typedef struct ib_pthread_s *ib_pthread_t;

typedef struct ib_pthread_join_context_s {
    ib_pthread_t   waiter;
    void      **value_ptr;
    ib_mach_port_t kport;
    ib_semaphore_t custom_stack_sema;
    bool        detached;
} ib_pthread_join_context_s, *ib_pthread_join_context_t;

struct ib_pthread_s {
    long sig;
    struct __darwin_pthread_handler_rec *__cleanup_stack;

    //
    // Fields protected by _pthread_list_lock
    //

    TAILQ_ENTRY(pthread_s) tl_plist;              // global thread list [aligned]
    struct ib_pthread_join_context_s *tl_join_ctx;
    void *tl_exit_value;
    uint8_t tl_policy;
    // pthread knows that tl_joinable bit comes immediately after tl_policy
    uint8_t
        tl_joinable:1,
        tl_joiner_cleans_up:1,
        tl_has_custom_stack:1,
        __tl_pad:5;
    uint16_t introspection;
    // MACH_PORT_NULL if no joiner
    // tsd[_PTHREAD_TSD_SLOT_MACH_THREAD_SELF] when has a joiner
    // MACH_PORT_DEAD if the thread exited
    uint32_t tl_exit_gate;
    struct sched_param tl_param;
    void *__unused_padding;

    //
    // Fields protected by pthread_t::lock
    //

    ib_pthread_lock lock;
    uint16_t max_tsd_key;
    uint16_t
        inherit:8,
        kernalloc:1,
        schedset:1,
        wqthread:1,
        wqkillset:1,
        __flags_pad:4;

    char pthread_name[MAXTHREADNAMESIZE];   // includes NUL [aligned]

    void  *(*fun)(void *);  // thread start routine
    void    *arg;           // thread start routine argument
    int      wq_nevents;    // wqthreads (workloop / kevent)
    bool     wq_outsideqos;
    uint8_t  canceled;      // 4597450 set if conformant cancelation happened
    uint16_t cancel_state;  // whether the thread can be canceled [atomic]
    errno_t  cancel_error;
    errno_t  err_no;        // thread-local errno

    void    *stackaddr;     // base of the stack (page aligned)
    void    *stackbottom;   // stackaddr - stacksize
    void    *freeaddr;      // stack/thread allocation base address
    size_t   freesize;      // stack/thread allocation size
    size_t   guardsize;     // guard page size in bytes

    // tsd-base relative accessed elements
    __attribute__((aligned(8)))
    uint64_t thread_id;     // 64-bit unique thread id

    /* Thread Specific Data slots
     *
     * The offset of this field from the start of the structure is difficult to
     * change on OS X because of a thorny bitcompat issue: mono has hard coded
     * the value into their source.  Newer versions of mono will fall back to
     * scanning to determine it at runtime, but there's lots of software built
     * with older mono that won't.  We will have to break them someday...
     */
    __attribute__ ((aligned (16)))
    /**
     tsd[0] = self;
     tsd[1] = errno_
     tsd[2] = mig_reply?
     tsd[3] = machThreadSelf?
     tsd[4] = someid (2303)
     tsd[7] = munge_token;
     
     */
    void *tsd[_EXTERNAL_POSIX_THREAD_KEYS_MAX + _INTERNAL_POSIX_THREAD_KEYS_MAX];
};

#endif /* pthread_types_14_h */
