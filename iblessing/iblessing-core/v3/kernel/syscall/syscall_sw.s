//
//  syscall_wrapper.s
//  iblessing-core
//
//  Created by bxl on 2021/11/27.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "syscall_sw.h"
#if defined (__arm__) || defined (__arm64__)
.globl _iokit_user_client_trap
.text
.align  2
_iokit_user_client_trap:
    mov x16, -100
    svc 0x80
    ret

.globl _pfz_exit
.text
.align  2
_pfz_exit:
    mov x16, -58
    svc 0x80
    ret

.globl _task_dyld_process_info_notify_get
.text
.align  2
_task_dyld_process_info_notify_get:
    mov x16, -13
    svc 0x80
    ret
#endif
