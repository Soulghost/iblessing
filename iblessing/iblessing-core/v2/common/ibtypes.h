//
//  iblessing-base.h
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef iblessing_base_h
#define iblessing_base_h

#include <stdio.h>
#include <string>
#include <memory>
#include <signal.h>

typedef int ib_return_t;

#define NS_IB_BEGIN namespace iblessing {
#define NS_IB_END }

#define IB_SUCCESS 0
#define IB_MACHO_LOAD_ERROR 1
#define IB_MEMORY_LOAD_ERROR_INVALID_MACHO 2
#define IB_INVALID_ARGUMENTS 3
#define IB_UNINIT_MODULE 4
#define IB_MEMORY_COPYOUT_ERROR 5
#define IB_MEMORY_MAPPING_ERROR 6
#define IB_OBJC_DATA_LOAD_ERROR 7

#define ensure_uc_mem_read(addr, bytes, size) do { \
if (uc_mem_read(uc, addr, bytes, size) != UC_ERR_OK) { \
    raise(SIGINT); \
    uc_debug_print_backtrace(uc); \
}\
} while (0)

#define ensure_uc_mem_write(addr, bytes, size) assert(uc_mem_write(uc, addr, bytes, size) == UC_ERR_OK)
#define ensure_uc_reg_read(reg, value) assert(uc_reg_read(uc, reg, value) == UC_ERR_OK)
#define ensure_uc_reg_write(reg, value) assert(uc_reg_write(uc, reg, value) == UC_ERR_OK)

#define SyscallBanner "[Stalker][+][Syscall]"

#endif /* iblessing_base_h */
