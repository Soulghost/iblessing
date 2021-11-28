//
//  syscall_wrapper_x64.s
//  iblessing-core
//
//  Created by bxl on 2021/11/27.
//  Copyright © 2021 soulghost. All rights reserved.
//


ENTRY(mach_trap_wrapper_kernelrpc_mach_vm_protect_trap)
    mov     %rcx, %r10
    mov     $100000Eh, %eax,
    syscall
    ret
