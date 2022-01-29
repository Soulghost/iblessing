//
//  libdispatch_defines.cpp
//  libdispatch_defines
//
//  Created by Soulghost on 2022/1/16.
//  Copyright © 2022 soulghost. All rights reserved.
//

#include <unistd.h>
#include <stdint.h>
#include "libdispatch_defines.hpp"

typedef uint32_t dispatch_tid;
typedef uint32_t dispatch_lock;
typedef uint32_t dispatch_qos_t;
typedef uint32_t dispatch_priority_t;

#define DISPATCH_DECL(name) typedef struct name##_s *name##_t
#define DISPATCH_DECL_SUBCLASS(name, base) typedef base##_t name##_t
#define DISPATCH_CACHELINE_SIZE 64u
#define DISPATCH_CACHELINE_ALIGN \
        __attribute__((__aligned__(DISPATCH_CACHELINE_SIZE)))
#define DISPATCH_ATOMIC64_ALIGN  __attribute__((aligned(8)))
#define DISPATCH_FUNCTION_POINTER
#define _OS_OBJECT_HEADER(isa, ref_cnt, xref_cnt) \
        isa; /* must be pointer-sized and use __ptrauth_objc_isa_pointer */ \
        int volatile ref_cnt; \
        int volatile xref_cnt

#define _OS_OBJECT_CLASS_HEADER() \
        void *_os_obj_objc_class_t[5]

#define OS_OBJECT_STRUCT_HEADER(x) \
    _OS_OBJECT_HEADER(\
    const struct x##_vtable_s *do_vtable, \
    do_ref_cnt, \
    do_xref_cnt)

#define _DISPATCH_OBJECT_HEADER(x) \
    struct _os_object_s _as_os_obj[0]; \
    OS_OBJECT_STRUCT_HEADER(dispatch_##x); \
    struct dispatch_##x##_s *volatile do_next; \
    struct dispatch_queue_s *do_targetq; \
    void *do_ctxt; \
    union { \
        dispatch_function_t DISPATCH_FUNCTION_POINTER do_finalizer; \
        void *do_introspection_ctxt; \
    }

#define DISPATCH_OBJECT_HEADER(x) \
    struct dispatch_object_s _as_do[0]; \
    _DISPATCH_OBJECT_HEADER(x)

#define DISPATCH_UNION_ASSERT(alias, st)
#define DISPATCH_CONCAT1(x,y) x ## y
#define DISPATCH_CONCAT(x,y) DISPATCH_CONCAT1(x,y)
#define DISPATCH_COUNT_ARGS1(z, a, b, c, d, e, f, g, h, cnt, ...) cnt
#define DISPATCH_COUNT_ARGS(...) DISPATCH_COUNT_ARGS1(, ## __VA_ARGS__, \
        _8, _7, _6, _5, _4, _3, _2, _1, _0)

#define DISPATCH_STRUCT_LE_2(a, b)        struct { a; b; }
#define DISPATCH_STRUCT_LE_3(a, b, c)     struct { a; b; c; }
#define DISPATCH_STRUCT_LE_4(a, b, c, d)  struct { a; b; c; d; }
#define DISPATCH_UNION_LE(alias, ...) \
        DISPATCH_UNION_ASSERT(alias, DISPATCH_CONCAT(DISPATCH_STRUCT_LE, \
                DISPATCH_COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)) \
        union { alias; DISPATCH_CONCAT(DISPATCH_STRUCT_LE, \
                DISPATCH_COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__); }

#define _DISPATCH_QUEUE_CLASS_HEADER(x, __pointer_sized_field__) \
    DISPATCH_OBJECT_HEADER(x); \
    __pointer_sized_field__; \
    DISPATCH_UNION_LE(uint64_t volatile dq_state, \
            dispatch_lock dq_state_lock, \
            uint32_t dq_state_bits \
    )

#define DISPATCH_QUEUE_ROOT_CLASS_HEADER(x) \
    struct dispatch_queue_s _as_dq[0]; \
    DISPATCH_QUEUE_CLASS_HEADER(x, \
            struct dispatch_object_s *volatile dq_items_tail); \
    int volatile dgq_thread_pool_size; \
    struct dispatch_object_s *volatile dq_items_head; \
    int volatile dgq_pending

#define DISPATCH_QUEUE_CLASS_HEADER(x, __pointer_sized_field__) \
    _DISPATCH_QUEUE_CLASS_HEADER(x, __pointer_sized_field__); \
    /* LP64 global queue cacheline boundary */ \
    unsigned long dq_serialnum; \
    const char *dq_label; \
    DISPATCH_UNION_LE(uint32_t volatile dq_atomic_flags, \
        const uint16_t dq_width, \
        const uint16_t __dq_opaque2 \
    ); \
    dispatch_priority_t dq_priority; \
    union { \
        struct dispatch_queue_specific_head_s *dq_specific_head; \
        struct dispatch_source_refs_s *ds_refs; \
        struct dispatch_timer_source_refs_s *ds_timer_refs; \
        struct dispatch_mach_recv_refs_s *dm_recv_refs; \
        struct dispatch_channel_callbacks_s const *dch_callbacks; \
    }; \
    int volatile dq_sref_cnt

#define OS_OBJECT_CLASS_DECL(name, ...) \
        struct name##_s; \
        struct name##_extra_vtable_s { \
            __VA_ARGS__; \
        }; \
        struct name##_vtable_s { \
            _OS_OBJECT_CLASS_HEADER(); \
            struct name##_extra_vtable_s _os_obj_vtable; \
        }; \
        OS_OBJECT_EXTRA_VTABLE_DECL(name, name) \
        extern const struct name##_vtable_s OS_OBJECT_CLASS_SYMBOL(name) \
                __asm__(OS_OBJC_CLASS_RAW_SYMBOL_NAME(OS_OBJECT_CLASS(name)))

#define DISPATCH_CLASS_DECL_BARE(name, cluster) \
        OS_OBJECT_CLASS_DECL(dispatch_##name, \
        DISPATCH_##cluster##_VTABLE_HEADER(dispatch_##name))

//typedef struct _os_object_vtable_s {
//    _OS_OBJECT_CLASS_HEADER();
//} _os_object_vtable_s;
//
//typedef struct _os_object_s {
//    _OS_OBJECT_HEADER(
//    const _os_object_vtable_s * os_obj_isa,
//    os_obj_ref_cnt,
//    os_obj_xref_cnt);
//} _os_object_s;
typedef void (*dispatch_function_t)(void *_Nullable);

//struct dispatch_object_s {
//    _DISPATCH_OBJECT_HEADER(object);
//};
//
//struct dispatch_queue_s {
//    DISPATCH_QUEUE_CLASS_HEADER(queue, void *__dq_opaque1);
//    /* 32bit hole on LP64 */
//} DISPATCH_ATOMIC64_ALIGN;
//
//struct dispatch_queue_global_s {
//    DISPATCH_QUEUE_ROOT_CLASS_HEADER(lane);
//} DISPATCH_CACHELINE_ALIGN;

DISPATCH_DECL(dispatch_queue);
DISPATCH_DECL_SUBCLASS(dispatch_queue_global, dispatch_queue);

#define DISPATCH_LANE_CLASS_HEADER(x) \
    struct dispatch_queue_s _as_dq[0]; \
    DISPATCH_QUEUE_CLASS_HEADER(x, \
            struct dispatch_object_s *volatile dq_items_tail); \
    dispatch_unfair_lock_s dq_sidelock; \
    struct dispatch_object_s *volatile dq_items_head; \
    uint32_t dq_side_suspend_cnt

#define DISPATCH_SOURCE_CLASS_HEADER(x) \
    DISPATCH_LANE_CLASS_HEADER(x); \
    uint16_t \
        /* set under the drain lock */ \
        ds_is_installed:1, \
        ds_latched:1, \
        dm_connect_handler_called:1, \
        dm_cancel_handler_called:1, \
        dm_is_xpc:1, \
        dm_arm_no_senders:1, \
        dm_made_sendrights:1, \
        dm_strict_reply:1, \
        __ds_flags_pad : 8; \
    uint16_t __dq_flags_separation[0]; \
    uint16_t \
        /* set under the send queue lock */ \
        dm_needs_mgr:1, \
        dm_disconnected:1, \
        __dm_flags_pad : 14

struct _dispatch_mach_s {
    DISPATCH_SOURCE_CLASS_HEADER(mach);
    void *dm_send_refs;
    void *dm_xpc_term_refs;
} DISPATCH_ATOMIC64_ALIGN;
