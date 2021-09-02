//
//  aarch64-machine.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/9/2.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-machine.hpp"
#include <iblessing-core/v2/vendor/capstone/capstone.h>

using namespace std;
using namespace iblessing;

#define UnicornStackTopAddr      0x300000000

// create disasm handle
static csh cs_handle;
static uc_hook insn_hook, memexp_hook;

static void insn_hook_callback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    void *codes = malloc(sizeof(uint32_t));
    uc_err err = uc_mem_read(uc, address, codes, sizeof(uint32_t));
    if (err != UC_ERR_OK) {
        free(codes);
        return;
    }

    cs_insn *insn = nullptr;
    size_t count = cs_disasm(cs_handle, (uint8_t *)codes, 4, address, 0, &insn);
    if (count != 1) {
        if (insn && count > 0) {
            cs_free(insn, count);
        }
        free(codes);
        assert(false);
        return;
    }
    
    printf("[Stalker] 0x%08llx %s %s\n", insn->address, insn->mnemonic, insn->op_str);
    
    free(codes);
}

static bool mem_exception_hook_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_WRITE_UNMAPPED) {
#define UC_PAGE_SIZE 0x1000
        uint64_t page_begin = address & ~(UC_PAGE_SIZE - 1);
        uc_mem_map(uc, page_begin, UC_PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE);
        
        // FIXME: fill zero
        void *dummy_bytes = calloc(1, size);
        uc_mem_write(uc, address, dummy_bytes, size);
    } else if (type == UC_MEM_FETCH_UNMAPPED) {
//        printf("Warn: [-] unmapped instruction at 0x%llx\n", address);
        assert(false);
    }
    return true;
}

int Aarch64Machine::callModule(shared_ptr<MachOModule> module, string symbolName) {
    if (symbolName.length() == 0) {
        printf("[-] error: does not support call entry-point");
        assert(false);
    }
    
    Symbol *symbol = module->symtab->getSymbolByName(symbolName);
    assert(symbol != nullptr);
    uint64_t symbolAddr = symbol->info->n_value;
    printf("[*] call symbol %s(0x%llx) in module %s\n", symbol->name.c_str(), symbolAddr, module->name.c_str());
    
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    
    // set capstone
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &cs_handle) == CS_ERR_OK);
    // enable detail
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    // setup hooks
    uc_hook_add(uc, &insn_hook, UC_HOOK_CODE, (void *)insn_hook_callback, NULL, 1, 0);
    uc_hook_add(uc, &memexp_hook, UC_HOOK_MEM_INVALID, (void *)mem_exception_hook_callback, NULL, 1, 0);
    
    // init context
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    
    printf("[*] execute in engine, pc = 0x%llx\n", symbolAddr);
    uc_err err = uc_emu_start(uc, symbolAddr, 0000000100007e84, 0, 0);
    printf("[*] execute in engine result %s\n", uc_strerror(err));
    return 0;
}
