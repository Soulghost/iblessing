//
//  UnicornARM64Runtime.cpp
//  iblessing
//
//  Created by soulghost on 2020/6/2.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "UnicornARM64Runtime.hpp"
#include "VirtualMemory.hpp"
#include <iblessing-core/vendor/unicorn/unicorn.h>

using namespace std;
using namespace iblessing;

#define Steps 9

/**
 mov x0, #0x1000
 ret
 */
#define RETURNCODE "\x00\x00\x82\xd2\xc0\x03\x5f\xd6"

static void hook_ins(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    void *buffer = malloc(16);
    uc_mem_read(uc, 0x1f0000000 - 0x30, buffer, 16);
    free(buffer);
    printf(">>> Tracing instruction at 0x%llx, instruction size = 0x%x\n", address, size);
    if (address == 0x100004088) {
        uc_mem_write(uc, 0x104637688, RETURNCODE, sizeof(RETURNCODE) - 1);
    } else if (address == 0x10000408c) {
        uint64_t x0 = 0;
        assert(uc_reg_read(uc, UC_ARM64_REG_X0, &x0) == UC_ERR_OK);
        assert(x0 == 0x1000);
    }
}


void UnicornARM64Runtime::testFunction(uint64_t address, uint64_t endaddr) {
    uc_engine *uc;
    uc_err err;
    
    printf("[*] Emulate ARM64 code\n");
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("[-] failed to open unicore engine, error %s\n", uc_strerror(err));
        return;
    }

    uc_mem_map(uc, 0x0000000100000000, (uint64_t)1024 * 1024 * 1024 * 4, UC_PROT_ALL);
    
    VirtualMemory *vm = VirtualMemory::progressDefault();
    uint64_t mainOff = address - vm->vmaddr_base;
    uint8_t *codes = vm->mappedFile + mainOff;
    uc_mem_write(uc, address, codes, Steps * sizeof(uint32_t));
    
    uint64_t sp = 0x1f0000000;
    uint64_t x21 = 0x11111111, x22 = 0x22222222;
    uint64_t x20 = 0x33333333, x19 = 0x44444444;
    uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
    uc_reg_write(uc, UC_ARM64_REG_X21, &x21);
    uc_reg_write(uc, UC_ARM64_REG_X22, &x22);
    uc_reg_write(uc, UC_ARM64_REG_X20, &x20);
    uc_reg_write(uc, UC_ARM64_REG_X19, &x19);
    
    uc_hook ins_trace;
    uc_hook_add(uc, &ins_trace, UC_HOOK_CODE, (void *)hook_ins, nullptr, address, address + Steps * sizeof(uint32_t), 0);
    
    err = uc_emu_start(uc, address, address + Steps * sizeof(uint32_t), -1, Steps);
    if (err) {
        printf("[-] failed to open unicore engine, error %s\n", uc_strerror(err));
        return;
    }
}
