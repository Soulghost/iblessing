//
//  syscall_helper_arm64.h
//  iblessing
//
//  Created by bxl on 2021/11/29.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef syscall_helper_arm64_h
#define syscall_helper_arm64_h

#define SWI_SYSCALL     0x80

#define kernel_trap(trap_name, trap_number, num_args) \
.globl _##trap_name                                           ;\
.text                                                         ;\
.align  2                                                     ;\
_##trap_name:                                                 ;\
    mov x16, #(trap_number)                                   ;\
    svc #SWI_SYSCALL                                          ;\
    ret;



#endif /* syscall_helper_arm64_h */
