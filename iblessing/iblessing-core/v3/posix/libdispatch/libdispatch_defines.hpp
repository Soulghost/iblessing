//
//  libdispatch_defines.hpp
//  libdispatch_defines
//
//  Created by Soulghost on 2022/1/16.
//  Copyright © 2022 soulghost. All rights reserved.
//

#ifndef libdispatch_defines_hpp
#define libdispatch_defines_hpp

//#include <stdio.h>

typedef uint32_t dispatch_tid;
typedef uint32_t dispatch_lock;
typedef uint32_t dispatch_qos_t;
typedef uint32_t dispatch_priority_t;
typedef unsigned long dispatch_mach_reason_t;
typedef uint32_t mach_error_t;
typedef void *dispatch_mach_msg_t;
typedef void (*dispatch_function_t)(void *_Nullable);
#define DISPATCH_ATOMIC64_ALIGN  __attribute__((aligned(8)))
#define DISPATCH_VTABLE_ENTRY(op) (* const op)
#define DISPATCH_FUNCTION_POINTER
struct dispatch_object_vtable_s {

};
struct dispatch_queue_vtable_s {

};
struct dispatch_lane_vtable_s {

};

typedef struct _os_object_vtable_s {
    void *_os_obj_objc_class_t[5];
} _os_object_vtable_s;

typedef struct _os_object_s {
    const _os_object_vtable_s * os_obj_isa;
    int volatile os_obj_ref_cnt;
    int volatile os_obj_xref_cnt;
} _os_object_s;

struct dispatch_queue_s;
struct dispatch_object_s {
    struct _os_object_s _as_os_obj[0];
    const struct dispatch_object_vtable_s *do_vtable;
    int volatile do_ref_cnt;
    int volatile do_xref_cnt;
    struct dispatch_object_s *volatile do_next;
    struct dispatch_queue_s *do_targetq;
    void *do_ctxt;
    union {
        dispatch_function_t do_finalizer;
        void *do_introspection_ctxt;
    };
};

#define TAILQ_HEAD(list_name, elem_type) \
    struct list_name { \
        struct elem_type *tq_first; \
        struct elem_type *tq_last; \
    }

#define TAILQ_ENTRY(elem_type) \
    struct { \
        struct elem_type *te_next; \
        struct elem_type *te_prev; \
    }

typedef struct dispatch_unfair_lock_s {
    dispatch_lock dul_lock;
} dispatch_unfair_lock_s, *dispatch_unfair_lock_t;

typedef struct dispatch_queue_specific_s {
    const void *dqs_key;
    void *dqs_ctxt;
    dispatch_function_t dqs_destructor;
    TAILQ_ENTRY(dispatch_queue_specific_s) dqs_entry;
} *dispatch_queue_specific_t;

typedef struct dispatch_queue_specific_head_s {
    dispatch_unfair_lock_s dqsh_lock;
    TAILQ_HEAD(, dispatch_queue_specific_s) dqsh_entries;
} *dispatch_queue_specific_head_t;

typedef void *dispatch_source_type_t;
typedef uintptr_t dispatch_unote_state_t;
typedef uint32_t dispatch_unote_ident_t;

#define os_atomic(type) type volatile

#define DISPATCH_UNOTE_CLASS_HEADER() \
    dispatch_source_type_t  du_type; \
    uintptr_t du_owner_wref; /* "weak" back reference to the owner object */ \
    os_atomic(dispatch_unote_state_t) du_state; \
    dispatch_unote_ident_t du_ident; \
    int8_t    du_filter; \
    uint8_t   du_is_direct : 1; \
    uint8_t   du_is_timer : 1; \
    uint8_t   du_has_extended_status : 1; \
    uint8_t   du_memorypressure_override : 1; \
    uint8_t   du_vmpressure_override : 1; \
    uint8_t   du_can_be_wlh : 1; \
    uint8_t   dmrr_handler_is_block : 1; \
    uint8_t   du_unused_flag : 1; \
    union { \
        uint8_t   du_timer_flags; \
        os_atomic(bool) dmsr_notification_armed; \
        bool dmr_reply_port_owned; \
    }; \
    uint8_t   du_unused; \
    uint32_t  du_fflags; \
    dispatch_priority_t du_priority

#define DISPATCH_SOURCE_REFS_HEADER() \
    DISPATCH_UNOTE_CLASS_HEADER(); \
    struct dispatch_continuation_s *volatile ds_handler[3]; \
    uint64_t ds_data DISPATCH_ATOMIC64_ALIGN; \
    uint64_t ds_pending_data DISPATCH_ATOMIC64_ALIGN

typedef struct dispatch_source_refs_s {
    DISPATCH_SOURCE_REFS_HEADER();
} *dispatch_source_refs_t;

#define DTH_ID_COUNT    2u
typedef struct dispatch_timer_source_s {
    union {
        struct {
            uint64_t target;
            uint64_t deadline;
        };
        uint64_t heap_key[DTH_ID_COUNT];
    };
    uint64_t interval;
} *dispatch_timer_source_t;

typedef enum {
    DISPATCH_CLOCK_UPTIME,
    DISPATCH_CLOCK_MONOTONIC,
    DISPATCH_CLOCK_WALL,
#define DISPATCH_CLOCK_COUNT  (DISPATCH_CLOCK_WALL + 1)
} dispatch_clock_t;

typedef struct dispatch_timer_config_s {
    struct dispatch_timer_source_s dtc_timer;
    dispatch_clock_t dtc_clock;
} *dispatch_timer_config_t;

typedef struct dispatch_timer_source_refs_s {
    DISPATCH_SOURCE_REFS_HEADER();
    struct dispatch_timer_source_s dt_timer;
    struct dispatch_timer_config_s *dt_pending_config;
    uint32_t dt_heap_entry[DTH_ID_COUNT];
} *dispatch_timer_source_refs_t;

typedef void (*dispatch_mach_handler_function_t)(void * context,
        dispatch_mach_reason_t reason, dispatch_mach_msg_t message,
        mach_error_t error);
struct dispatch_mach_recv_refs_s {
    DISPATCH_UNOTE_CLASS_HEADER();
    dispatch_mach_handler_function_t dmrr_handler_func;
    void *dmrr_handler_ctxt;
};
typedef struct dispatch_mach_recv_refs_s *dispatch_mach_recv_refs_t;

typedef struct dispatch_channel_callbacks_s {
#define DISPATCH_CHANNEL_CALLBACKS_VERSION 1ul
    /*! @field dcc_version
     *
     * @abstract
     * Version of the callbacks, used for binary compatibilty.
     * This must be set to DISPATCH_CHANNEL_CALLBACKS_VERSION
     */
    unsigned long dcc_version;

    /*! @field dcc_probe
     *
     * @abstract
     * This callback is called when GCD is considering whether it should wakeup
     * the channel.
     *
     * @discussion
     * This function may be called from ANY context. It may be called
     * concurrently from several threads, it may be called concurrently with
     * a call to other channel callbacks.
     *
     * Reasons for this function to be called include:
     * - the channel became non empty,
     * - the channel is receiving a Quality of Service override to resolve
     *   a priority inversion,
     * - dispatch_activate() or dispatch_resume() was called,
     * - dispatch_channel_wakeup() was called.
     *
     * The implementation of this callback should be idempotent, and as cheap
     * as possible, avoiding taking locks if possible. A typical implementation
     * will perform a single atomic state look to determine what answer to
     * return. Possible races or false positives can be later be debounced in
     * dcc_invoke which is synchronized.
     *
     * Calling dispatch_channel_wakeup() from the context of this call is
     * incorrect and will result in undefined behavior. Instead, it should be
     * called in response to external events, in order to cause the channel to
     * re-evaluate the `dcc_probe` hook.
     *
     * param channel
     * The channel that is being probed.
     *
     * param context
     * The context associated with the channel.
     *
     * returns
     * - true if the dispatch channel can be woken up according to the other
     *   runtime rules
     *
     * - false if the dispatch channel would not be able to make progress if
     *   woken up. A subsequent explicit call to dispatch_channel_wakeup() will
     *   be required when this condition has changed.
     */
    void *dcc_probe;

    /*! @field dcc_invoke
     *
     * @abstract
     * This callback is called when a dispatch channel is being drained.
     *
     * @discussion
     * This callback is where the state machine for the channel can
     * be implemented using dispatch_channel_foreach_work_item_peek()
     * and dispatch_channel_drain().
     *
     * Note that if this function returns true, it must have called
     * dispatch_channel_drain() exactly once. It is valid not to call
     * peek nor drain if false is returned.
     *
     * param channel
     * The channel that has been invoked.
     *
     * param invoke_context
     * An opaque data structure that must be passed back to
     * dispatch_channel_foreach_work_item_peek() and dispatch_channel_drain().
     *
     * param context
     * The context associated with the channel.
     *
     * returns
     * - true if the channel can drain further
     * - false if an explicit call to dispatch_channel_wakeup() is required
     *   for the channel to be able to drain items again. A subsequent explicit
     *   call to dispatch_channel_wakeup() will be required when this condition
     *   has changed.
     */
    void *dcc_invoke;

    /*! @field dcc_acknowledge_cancel
     *
     * @abstract
     * This optional callback is called when the channel has been cancelled
     * until that cancellation is acknowledged.
     *
     * @discussion
     * If this callback isn't set, the channel cancelation is implicit and can
     * be tested with dispatch_channel_testcancel().
     *
     * When this callback is set, it will be called as soon as cancelation has
     * been noticed. When it is called, it is called from a context serialized
     * with `dcc_invoke`, or from `dcc_invoke` itself.
     *
     * Returning `false` causes the dispatch channel to stop its invocation
     * early. A subsequent explicit call to dispatch_channel_wakeup() will be
     * required when the cancellation can be acknowledged.
     *
     * param channel
     * The channel that has been invoked.
     *
     * param context
     * The context associated with the channel.
     *
     * returns
     * Whether the cancellation was acknowledged.
     */
    void *dcc_acknowledge_cancel;
} const *dispatch_channel_callbacks_t;

struct dispatch_queue_s {
    struct dispatch_object_s _as_do[0];
    struct _os_object_s _as_os_obj[0];
    const struct dispatch_queue_vtable_s *do_vtable;
    int volatile do_ref_cnt;
    int volatile do_xref_cnt;
    struct dispatch_queue_s *volatile do_next;
    struct dispatch_queue_s *do_targetq;
    void *do_ctxt;
    union { dispatch_function_t do_finalizer; void *do_introspection_ctxt; };
    void *__dq_opaque1;
    union { uint64_t volatile dq_state; struct { dispatch_lock dq_state_lock; uint32_t dq_state_bits; }; };
    unsigned long dq_serialnum;
    const char *dq_label;
    union { uint32_t volatile dq_atomic_flags; struct { const uint16_t dq_width; const uint16_t __dq_opaque2; }; };
    dispatch_priority_t dq_priority;
    union {
        struct dispatch_queue_specific_head_s *dq_specific_head;
        struct dispatch_source_refs_s *ds_refs;
        struct dispatch_timer_source_refs_s *ds_timer_refs;
        struct dispatch_mach_recv_refs_s *dm_recv_refs;
        struct dispatch_channel_callbacks_s const *dch_callbacks;
    };
    int volatile dq_sref_cnt;
} __attribute__((aligned(8)));

struct dispatch_queue_global_s {
    struct dispatch_queue_s _as_dq[0];
    struct dispatch_object_s _as_do[0];
    struct _os_object_s _as_os_obj[0];
    const struct dispatch_lane_vtable_s *do_vtable;
    int volatile do_ref_cnt;
    int volatile do_xref_cnt;
    struct dispatch_lane_s *volatile do_next;
    struct dispatch_queue_s *do_targetq;
    void *do_ctxt;
    union { dispatch_function_t do_finalizer; void *do_introspection_ctxt; };
    struct dispatch_object_s *volatile dq_items_tail;
    union { uint64_t volatile dq_state; struct { dispatch_lock dq_state_lock; uint32_t dq_state_bits; }; };
    unsigned long dq_serialnum;
    const char *dq_label;
    union { uint32_t volatile dq_atomic_flags;
    struct { const uint16_t dq_width; const uint16_t __dq_opaque2; }; };
    dispatch_priority_t dq_priority;
    union {
        struct dispatch_queue_specific_head_s *dq_specific_head;
        struct dispatch_source_refs_s *ds_refs;
        struct dispatch_timer_source_refs_s *ds_timer_refs;
        struct dispatch_mach_recv_refs_s *dm_recv_refs;
        struct dispatch_channel_callbacks_s const *dch_callbacks;
    };
    int volatile dq_sref_cnt;
    int volatile dgq_thread_pool_size;
    struct dispatch_object_s *volatile dq_items_head;
    int volatile dgq_pending;
} __attribute__((__aligned__(64u)));

struct dispatch_mach_s {
    struct dispatch_queue_s _as_dq[0]; struct dispatch_object_s _as_do[0]; struct _os_object_s _as_os_obj[0]; const struct dispatch_mach_vtable_s *do_vtable; int volatile do_ref_cnt; int volatile do_xref_cnt; struct dispatch_mach_s *volatile do_next; struct dispatch_queue_s *do_targetq; void *do_ctxt; union { dispatch_function_t do_finalizer; void *do_introspection_ctxt; }; struct dispatch_object_s *volatile dq_items_tail; union { uint64_t volatile dq_state; struct { dispatch_lock dq_state_lock; uint32_t dq_state_bits; }; }; unsigned long dq_serialnum; const char *dq_label; union { uint32_t volatile dq_atomic_flags; struct { const uint16_t dq_width; const uint16_t __dq_opaque2; }; }; dispatch_priority_t dq_priority; union { struct dispatch_queue_specific_head_s *dq_specific_head; struct dispatch_source_refs_s *ds_refs; struct dispatch_timer_source_refs_s *ds_timer_refs; struct dispatch_mach_recv_refs_s *dm_recv_refs; struct dispatch_channel_callbacks_s const *dch_callbacks; }; int volatile dq_sref_cnt; dispatch_unfair_lock_s dq_sidelock; struct dispatch_object_s *volatile dq_items_head; uint32_t dq_side_suspend_cnt; uint16_t ds_is_installed:1, ds_latched:1, dm_connect_handler_called:1, dm_cancel_handler_called:1, dm_is_xpc:1, dm_arm_no_senders:1, dm_made_sendrights:1, dm_strict_reply:1, __ds_flags_pad : 8; uint16_t __dq_flags_separation[0]; uint16_t dm_needs_mgr:1, dm_disconnected:1, __dm_flags_pad : 14;
    void *dm_send_refs;
    void *dm_xpc_term_refs;
} __attribute__((aligned(8)));

struct kevent_qos_s
{
  uint64_t ident;
  int16_t filter;
  uint16_t flags;
  int32_t qos;
  uint64_t udata;
  uint32_t fflags;
  uint32_t xflags;
  int64_t data;
  uint64_t ext[4];
};

/*
 * Filter types
 */
#define EVFILT_READ             (-1)
#define EVFILT_WRITE            (-2)
#define EVFILT_AIO              (-3)    /* attached to aio requests */
#define EVFILT_VNODE            (-4)    /* attached to vnodes */
#define EVFILT_PROC             (-5)    /* attached to struct proc */
#define EVFILT_SIGNAL           (-6)    /* attached to struct proc */
#define EVFILT_TIMER            (-7)    /* timers */
#define EVFILT_MACHPORT         (-8)    /* Mach portsets */
#define EVFILT_FS               (-9)    /* Filesystem events */
#define EVFILT_USER             (-10)   /* User events */


#endif /* libdispatch_defines_hpp */
