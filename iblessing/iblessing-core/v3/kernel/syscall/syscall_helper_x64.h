//
//  syscall_wrapper_x64.h
//  iblessing-core
//
//  Created by bxl on 2021/11/29.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef syscall_helper_x64_h
#define syscall_helper_x64_h


#define SYSCALL_CLASS_SHIFT    24
#define SYSCALL_CLASS_MASK    (0xFF << SYSCALL_CLASS_SHIFT)
#define SYSCALL_NUMBER_MASK    (~SYSCALL_CLASS_MASK)

#define    I386_SYSCALL_CLASS_MASK        SYSCALL_CLASS_MASK
#define    I386_SYSCALL_ARG_BYTES_SHIFT    (16)
#define    I386_SYSCALL_ARG_DWORDS_SHIFT    (I386_SYSCALL_ARG_BYTES_SHIFT + 2)
#define    I386_SYSCALL_ARG_BYTES_NUM    (64) /* Must be <= sizeof(uu_arg) */
#define    I386_SYSCALL_ARG_DWORDS_MASK    ((I386_SYSCALL_ARG_BYTES_NUM >> 2) -1)
#define    I386_SYSCALL_ARG_BYTES_MASK    (((I386_SYSCALL_ARG_BYTES_NUM -1)&~0x3) << I386_SYSCALL_ARG_BYTES_SHIFT)
#define    I386_SYSCALL_NUMBER_MASK    (0xFFFF)

#define SYSCALL_CLASS_NONE    0    /* Invalid */
#define SYSCALL_CLASS_MACH    1    /* Mach */
#define SYSCALL_CLASS_UNIX    2    /* Unix/BSD */
#define SYSCALL_CLASS_MDEP    3    /* Machine-dependent */
#define SYSCALL_CLASS_DIAG    4    /* Diagnostics */
#define SYSCALL_CLASS_IPC    5    /* Mach IPC */

/* Macros to simpllfy constructing syscall numbers. */
#define SYSCALL_CONSTRUCT_MACH(syscall_number) \
           ((SYSCALL_CLASS_MACH << SYSCALL_CLASS_SHIFT) | \
            (SYSCALL_NUMBER_MASK & (syscall_number)))
#define SYSCALL_CONSTRUCT_UNIX(syscall_number) \
           ((SYSCALL_CLASS_UNIX << SYSCALL_CLASS_SHIFT) | \
            (SYSCALL_NUMBER_MASK & (syscall_number)))
#define SYSCALL_CONSTRUCT_MDEP(syscall_number) \
           ((SYSCALL_CLASS_MDEP << SYSCALL_CLASS_SHIFT) | \
            (SYSCALL_NUMBER_MASK & (syscall_number)))
#define SYSCALL_CONSTRUCT_DIAG(syscall_number) \
           ((SYSCALL_CLASS_DIAG << SYSCALL_CLASS_SHIFT) | \
            (SYSCALL_NUMBER_MASK & (syscall_number)))

#define kernel_trap(trap_name,trap_number,number_args) \
.globl    _##trap_name                    ;\
_##trap_name:                            ;\
    movq    %rcx, %r10    ;\
    movl    $ SYSCALL_CONSTRUCT_MACH(-##trap_number), %eax    ;\
    syscall        ;\
    ret;

#endif /* syscall_helper_x64_h */
