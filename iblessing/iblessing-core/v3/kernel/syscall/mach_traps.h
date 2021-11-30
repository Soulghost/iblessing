//
//  mach_traps.h
//  iblessing
//
//  Created by bxl on 2021/11/29.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef mach_traps_h
#define mach_traps_h

#include <mach/mach.h>
#include <unistd.h>
#include <stdlib.h>
#include <mach/kern_return.h>


#define MACH_TRAP_TABLE_COUNT   128

typedef struct {
    int             mach_trap_arg_count; /* Number of trap arguments (Arch independant) */
    kern_return_t   (*mach_trap_function)(void *);
    int             mach_trap_u32_words; /* number of 32-bit words to copyin for U32 */
    const char*     mach_trap_name;
} mach_trap_t;

extern const mach_trap_t mach_trap_table[];

#define    MACH_TRAP(name, arg_count, u32_arg_words, munge32)    \
    { (arg_count), (name), (u32_arg_words), #name  }

extern mach_port_name_t mach_reply_port(void);

extern mach_port_name_t thread_get_special_reply_port(void);

extern mach_port_name_t thread_self_trap(void);

extern mach_port_name_t host_self_trap(void);

extern mach_msg_return_t mach_msg_trap(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_name_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_name_t notify);

extern mach_msg_return_t mach_msg_overwrite_trap(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_name_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_msg_priority_t priority,
    mach_msg_header_t *rcv_msg,
    mach_msg_size_t rcv_limit);

extern kern_return_t semaphore_signal_trap(
    mach_port_name_t signal_name);

extern kern_return_t semaphore_signal_all_trap(
    mach_port_name_t signal_name);

extern kern_return_t semaphore_signal_thread_trap(
    mach_port_name_t signal_name,
    mach_port_name_t thread_name);

extern kern_return_t semaphore_wait_trap(
    mach_port_name_t wait_name);

extern kern_return_t semaphore_wait_signal_trap(
    mach_port_name_t wait_name,
    mach_port_name_t signal_name);

extern kern_return_t semaphore_timedwait_trap(
    mach_port_name_t wait_name,
    unsigned int sec,
    clock_res_t nsec);

extern kern_return_t semaphore_timedwait_signal_trap(
    mach_port_name_t wait_name,
    mach_port_name_t signal_name,
    unsigned int sec,
    clock_res_t nsec);


extern kern_return_t clock_sleep_trap(
    mach_port_name_t clock_name,
    sleep_type_t sleep_type,
    int sleep_sec,
    int sleep_nsec,
    mach_timespec_t *wakeup_time);

extern kern_return_t _kernelrpc_mach_vm_allocate_trap(
    mach_port_name_t target,
    mach_vm_offset_t *addr,
    mach_vm_size_t size,
    int flags);

extern kern_return_t _kernelrpc_mach_vm_deallocate_trap(
    mach_port_name_t target,
    mach_vm_address_t address,
    mach_vm_size_t size
    );

extern kern_return_t task_dyld_process_info_notify_get(
    mach_port_name_array_t names_addr,
    natural_t *names_count_addr
    );

extern kern_return_t _kernelrpc_mach_vm_protect_trap(
    mach_port_name_t target,
    mach_vm_address_t address,
    mach_vm_size_t size,
    boolean_t set_maximum,
    vm_prot_t new_protection
    );

extern kern_return_t _kernelrpc_mach_vm_map_trap(
    mach_port_name_t target,
    mach_vm_offset_t *address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_prot_t cur_protection
    );

extern kern_return_t _kernelrpc_mach_vm_purgable_control_trap(
    mach_port_name_t target,
    mach_vm_offset_t address,
    vm_purgable_t control,
    int *state);

extern kern_return_t _kernelrpc_mach_port_allocate_trap(
    mach_port_name_t target,
    mach_port_right_t right,
    mach_port_name_t *name
    );

extern kern_return_t _kernelrpc_mach_port_deallocate_trap(
    mach_port_name_t target,
    mach_port_name_t name
    );

extern kern_return_t _kernelrpc_mach_port_mod_refs_trap(
    mach_port_name_t target,
    mach_port_name_t name,
    mach_port_right_t right,
    mach_port_delta_t delta
    );

extern kern_return_t _kernelrpc_mach_port_move_member_trap(
    mach_port_name_t target,
    mach_port_name_t member,
    mach_port_name_t after
    );

extern kern_return_t _kernelrpc_mach_port_insert_right_trap(
    mach_port_name_t target,
    mach_port_name_t name,
    mach_port_name_t poly,
    mach_msg_type_name_t polyPoly
    );

extern kern_return_t _kernelrpc_mach_port_get_attributes_trap(
    mach_port_name_t target,
    mach_port_name_t name,
    mach_port_flavor_t flavor,
    mach_port_info_t port_info_out,
    mach_msg_type_number_t *port_info_outCnt
    );

extern kern_return_t _kernelrpc_mach_port_insert_member_trap(
    mach_port_name_t target,
    mach_port_name_t name,
    mach_port_name_t pset
    );

extern kern_return_t _kernelrpc_mach_port_extract_member_trap(
    mach_port_name_t target,
    mach_port_name_t name,
    mach_port_name_t pset
    );

extern kern_return_t _kernelrpc_mach_port_construct_trap(
    mach_port_name_t target,
    mach_port_options_t *options,
    uint64_t context,
    mach_port_name_t *name
    );

extern kern_return_t _kernelrpc_mach_port_destruct_trap(
    mach_port_name_t target,
    mach_port_name_t name,
    mach_port_delta_t srdelta,
    uint64_t guard
    );

extern kern_return_t _kernelrpc_mach_port_guard_trap(
    mach_port_name_t target,
    mach_port_name_t name,
    uint64_t guard,
    boolean_t strict
    );

extern kern_return_t _kernelrpc_mach_port_unguard_trap(
    mach_port_name_t target,
    mach_port_name_t name,
    uint64_t guard
    );

extern kern_return_t mach_generate_activity_id(
    mach_port_name_t target,
    int count,
    uint64_t *activity_id
    );

extern kern_return_t macx_swapon(
    uint64_t filename,
    int flags,
    int size,
    int priority);

extern kern_return_t macx_swapoff(
    uint64_t filename,
    int flags);

extern kern_return_t macx_triggers(
    int hi_water,
    int low_water,
    int flags,
    mach_port_t alert_port);

extern kern_return_t macx_backing_store_suspend(
    boolean_t suspend);

extern kern_return_t macx_backing_store_recovery(
    int pid);

extern boolean_t swtch_pri(int pri);

extern boolean_t swtch(void);

extern kern_return_t thread_switch(
    mach_port_name_t thread_name,
    int option,
    mach_msg_timeout_t option_time);

extern mach_port_name_t task_self_trap(void);

extern kern_return_t host_create_mach_voucher_trap(
    mach_port_name_t host,
    mach_voucher_attr_raw_recipe_array_t recipes,
    int recipes_size,
    mach_port_name_t *voucher);

extern kern_return_t mach_voucher_extract_attr_recipe_trap(
    mach_port_name_t voucher_name,
    mach_voucher_attr_key_t key,
    mach_voucher_attr_raw_recipe_t recipe,
    mach_msg_type_number_t *recipe_size);

extern kern_return_t _kernelrpc_mach_port_type_trap(
    ipc_space_t task,
    mach_port_name_t name,
    mach_port_type_t *ptype);

extern kern_return_t _kernelrpc_mach_port_request_notification_trap(
    ipc_space_t task,
    mach_port_name_t name,
    mach_msg_id_t msgid,
    mach_port_mscount_t sync,
    mach_port_name_t notify,
    mach_msg_type_name_t notifyPoly,
    mach_port_name_t *previous);

/*
 *    Obsolete interfaces.
 */

extern kern_return_t task_for_pid(
    mach_port_name_t target_tport,
    int pid,
    mach_port_name_t *t);

extern kern_return_t task_name_for_pid(
    mach_port_name_t target_tport,
    int pid,
    mach_port_name_t *tn);

extern kern_return_t pid_for_task(
    mach_port_name_t t,
    int *x);

extern kern_return_t debug_control_port_for_pid(
    mach_port_name_t target_tport,
    int pid,
    mach_port_name_t *t);


#pragma mark -

extern kern_return_t mach_timebase_info_trap(user_addr_t info);

extern kern_return_t mach_wait_until(uint64_t deadline);

extern mach_port_name_t mk_timer_create(void);

extern kern_return_t mk_timer_destroy(mach_port_name_t name);

extern kern_return_t mk_timer_arm(mach_port_name_t name, uint64_t expire_time);

extern kern_return_t mk_timer_arm_leeway(mach_port_name_t name, uint64_t mk_timer_flags, uint64_t expire_time, uint64_t mk_leeway);

extern kern_return_t mk_timer_cancel(mach_port_name_t name, user_addr_t result_time);

extern kern_return_t iokit_user_client_trap(void * userClientRef, uint32_t index, void * p1, void * p2, void * p3, void * p4, void * p5, void * p6);

extern kern_return_t pfz_exit(void);

#endif /* mach_traps_h */
