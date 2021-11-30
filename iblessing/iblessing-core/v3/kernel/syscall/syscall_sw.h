//
//  syscall_sw.h
//  iblessing
//
//  Created by bxl on 2021/11/29.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef syscall_sw_h
#define syscall_sw_h

#ifdef __x86_64__
#include "syscall_helper_x64.h"
#else
#include "syscall_helper_arm64.h"
#endif

/*
 *    These trap numbers should be taken from the
 *    table in <kern/syscall_sw.c>.
 */

/*
 * i386 and x86_64 just load of the stack or use
 * registers in order; no munging is required,
 * and number of args is ignored.  ARM loads args
 * into registers beyond r3, unlike the normal
 * procedure call standard; we pad for 64-bit args.
 */
kernel_trap(_kernelrpc_mach_vm_allocate_trap,-10,5) /* 4 args, +1 for mach_vm_size_t */
kernel_trap(_kernelrpc_mach_vm_purgable_control_trap,-11,5) /* 4 args, +1 for mach_vm_offset_t */
kernel_trap(_kernelrpc_mach_vm_deallocate_trap,-12,5) /* 3 args, +2 for mach_vm_size_t and mach_vm_address_t */
kernel_trap(task_dyld_process_info_notify_get,-13,4) /* 2 args, +2 for mach_vm_address_t */
kernel_trap(_kernelrpc_mach_vm_protect_trap,-14,7) /* 5 args, +2 for mach_vm_address_t and mach_vm_size_t */
kernel_trap(_kernelrpc_mach_vm_map_trap,-15,9)
kernel_trap(_kernelrpc_mach_port_allocate_trap,-16,3)
/* mach_port_destroy */
kernel_trap(_kernelrpc_mach_port_deallocate_trap,-18,2)
kernel_trap(_kernelrpc_mach_port_mod_refs_trap,-19,4)
kernel_trap(_kernelrpc_mach_port_move_member_trap,-20,3)
kernel_trap(_kernelrpc_mach_port_insert_right_trap,-21,4)
kernel_trap(_kernelrpc_mach_port_insert_member_trap,-22,3)
kernel_trap(_kernelrpc_mach_port_extract_member_trap,-23,3)
kernel_trap(_kernelrpc_mach_port_construct_trap,-24,5)
kernel_trap(_kernelrpc_mach_port_destruct_trap,-25,5)

kernel_trap(mach_reply_port,-26,0)
kernel_trap(thread_self_trap,-27,0)
kernel_trap(task_self_trap,-28,0)
kernel_trap(host_self_trap,-29,0)

kernel_trap(mach_msg_trap,-31,7)
kernel_trap(mach_msg_overwrite_trap,-32,9)
kernel_trap(semaphore_signal_trap, -33, 1)
kernel_trap(semaphore_signal_all_trap, -34, 1)
kernel_trap(semaphore_signal_thread_trap, -35, 2)
kernel_trap(semaphore_wait_trap,-36,1)
kernel_trap(semaphore_wait_signal_trap,-37,2)
kernel_trap(semaphore_timedwait_trap,-38,3)
kernel_trap(semaphore_timedwait_signal_trap,-39,4)

kernel_trap(_kernelrpc_mach_port_get_attributes_trap,-40,5)
kernel_trap(_kernelrpc_mach_port_guard_trap,-41,5)
kernel_trap(_kernelrpc_mach_port_unguard_trap,-42,4)
kernel_trap(mach_generate_activity_id, -43, 3)

kernel_trap(task_name_for_pid,-44,3)
kernel_trap(task_for_pid,-45,3)
kernel_trap(pid_for_task,-46,2)

#if defined(__LP64__)
kernel_trap(macx_swapon,-48, 4)
kernel_trap(macx_swapoff,-49, 2)
#else    /* __LP64__ */
kernel_trap(macx_swapon,-48, 5)
kernel_trap(macx_swapoff,-49, 3)
#endif    /* __LP64__ */
kernel_trap(thread_get_special_reply_port,-50,0)
kernel_trap(macx_triggers,-51, 4)
kernel_trap(macx_backing_store_suspend,-52, 1)
kernel_trap(macx_backing_store_recovery,-53, 1)

/* These are currently used by pthreads even on LP64 */
/* But as soon as that is fixed - they will go away there */
kernel_trap(swtch_pri,-59,1)
kernel_trap(swtch,-60,0)

kernel_trap(syscall_thread_switch,-61,3)
kernel_trap(clock_sleep_trap,-62,5)

/* voucher traps */
kernel_trap(host_create_mach_voucher_trap,-70,4)
/* mach_voucher_extract_attr_content */
kernel_trap(mach_voucher_extract_attr_recipe_trap,-72,4)
/* mach_voucher_extract_all_attr_recipes */
/* mach_voucher_attr_command */
/* mach_voucher_debug_info */

/* more mach_port traps */
kernel_trap(_kernelrpc_mach_port_type_trap,-76,3)
kernel_trap(_kernelrpc_mach_port_request_notification_trap,-77,7)

kernel_trap(mach_timebase_info_trap,-89,1)

#if        defined(__LP64__)
/* unit64_t arguments passed in one register in LP64 */
kernel_trap(mach_wait_until,-90,1)
#else    /* __LP64__ */
kernel_trap(mach_wait_until,-90,2)
#endif    /* __LP64__ */

kernel_trap(mk_timer_create,-91,0)
kernel_trap(mk_timer_destroy,-92,1)

#if        defined(__LP64__)
/* unit64_t arguments passed in one register in LP64 */
kernel_trap(mk_timer_arm,-93,2)
#else    /* __LP64__ */
kernel_trap(mk_timer_arm,-93,3)
#endif    /* __LP64__ */

kernel_trap(mk_timer_cancel,-94,2)
#if        defined(__LP64__)
kernel_trap(mk_timer_arm_leeway,-95,4)
#else
kernel_trap(mk_timer_arm_leeway,-95,7)
#endif
kernel_trap(debug_control_port_for_pid,-96,3)

#pragma mark -
kernel_trap(iokit_user_client_trap,-100,8)
kernel_trap(pfz_exit, -58, 0)



#endif /* syscall_sw_h */
