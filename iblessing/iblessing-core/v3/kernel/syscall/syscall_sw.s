//
//  syscall_wrapper_x64.s
//  iblessing-core
//
//  Created by bxl on 2021/11/27.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "syscall_sw.h"

/*
#define def_mach_trap_wrapper(n) \
.global _mach_trap_wrapper_##n; \
_mach_trap_wrapper_##n: \
mov     %rcx, %r10; \
mov     $0x1000000, %eax; \
add     $##n , %eax; \
syscall; \
ret


.global _mach_trap_wrapper_kernelrpc_mach_vm_protect_trap;
_mach_trap_wrapper_kernelrpc_mach_vm_protect_trap:
    mov     %rcx, %r10
    mov     $0x100000E, %eax
    syscall
    ret

.global _mach_trap_wrapper_task_self_trap

_mach_trap_wrapper_task_self_trap:
    mov     %rcx, %r10
    mov     $0x100001C, %eax
    syscall
    ret

*/

