//
//  aarch64-machine.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/9/2.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-machine.hpp"
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/vendor/capstone/capstone.h>

using namespace std;
using namespace iblessing;

#define UnicornStackTopAddr      0x300000000

// global
static map<uc_engine *, Aarch64Machine *> uc2instance;

// create disasm handle
static csh cs_handle;
static uc_hook insn_hook, intr_hook, memexp_hook;

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
    
    string comments = "";
    if (strcmp(insn->mnemonic, "blr") == 0) {
        uint64_t regValue = 0;
        assert(uc_reg_read(uc, insn->detail->arm64.operands[1].reg, &regValue) == UC_ERR_OK);
        comments = StringUtils::format("#0x%llx", regValue);
    } else {
        if (address == 0x100E3A7FC) {
            int w8;
            assert(uc_reg_read(uc, UC_ARM64_REG_W8, &w8) == UC_ERR_OK);
            comments = StringUtils::format("w8 = %d", w8);
        } else if (address == 0x100E3A888) {
            int w9;
            assert(uc_reg_read(uc, UC_ARM64_REG_W8, &w9) == UC_ERR_OK);
            comments = StringUtils::format("w9 = %d", w9);
        } else if (address == 0x100E3A89C) {
            int w20;
            assert(uc_reg_read(uc, UC_ARM64_REG_W20, &w20) == UC_ERR_OK);
            comments = StringUtils::format("w20 = %d", w20);
        } else if (address == 0x100E3A878) {
            int w9;
            assert(uc_reg_read(uc, UC_ARM64_REG_W9, &w9) == UC_ERR_OK);
            comments = StringUtils::format("w9 = %d(0x%x)", w9, w9);
        }
    }
    
    shared_ptr<MachOModule> module = uc2instance[uc]->loader->findModuleByAddr(address);
    if (module) {
        printf("[Stalker] 0x%08llx %s %s ; %s (%s 0x%llx)\n", insn->address, insn->mnemonic, insn->op_str, comments.c_str(), module->name.c_str(), module->addr);
    } else {
        printf("[Stalker] 0x%08llx %s %s ; %s\n", insn->address, insn->mnemonic, insn->op_str, comments.c_str());
    }
    
    free(codes);
}

static void uc_hookintr_callback(uc_engine *uc, uint32_t intno, void *user_data) {
    void *codes = malloc(sizeof(uint32_t));
    uint64_t pc = 0;
    assert(uc_reg_read(uc, UC_ARM64_REG_PC, &pc) == UC_ERR_OK);
    uc_err err = uc_mem_read(uc, pc, codes, sizeof(uint32_t));
    if (err != UC_ERR_OK) {
        free(codes);
        return;
    }
    
    uint32_t code;
    assert(uc_mem_read(uc, pc - sizeof(uint32_t), &code, 4) == UC_ERR_OK);
    
    uint32_t swi = (code >> 5) & 0xffff;
    Aarch64Machine *that = uc2instance[uc];
    assert(that->svcManager->handleSVC(uc, intno, swi, user_data) == true);
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
        return true;
    } else if (type == UC_MEM_FETCH_UNMAPPED) {
        // FIXME: pthread [Stalker] 0x100f38410 mrs x8, tpidrro_el0 ;
        // see unidbg-ios/src/main/java/com/github/unidbg/ios/MachOLoader.java initializeTSD
//        printf("Warn: [-] unmapped instruction at 0x%llx\n", address);
        assert(false);
    }
    assert(false);
    return false;
}

void Aarch64Machine::initModule(shared_ptr<MachOModule> module) {
    if (module->hasInit) {
        return;
    }
    printf("[+] init module %s\n", module->name.c_str());
    // FIXME: vars, envs
    printf("  [+] process routines\n");
    for (MachORoutine &routine: module->routines) {
        uint64_t addr = routine.addr;
        printf("  [*] execute routine in engine, pc = 0x%llx\n", addr);
        uc_err err = uc_emu_start(uc, addr, 0, 0, 0);
        printf("  [*] execute routine in engine result %s\n", uc_strerror(err));
    }
    printf("  [+] process mod_init_funcs\n");
    for (MachODynamicLibrary &lib : module->dynamicLibraryDependencies) {
        shared_ptr<MachOModule> dependModule = loader->findModuleByName(lib.name);
        assert(dependModule != nullptr);
        initModule(dependModule);
    }
    for (MachOModInitFunc &initFunc : module->modInitFuncs) {
        uint64_t addr = initFunc.addr;
        printf("  [*] execute mod_init_func in engine, pc = 0x%llx\n", addr);
        uc_err err = uc_emu_start(uc, addr, 0, 0, 0);
        printf("  [*] execute mod_init_func in engine result %s\n", uc_strerror(err));
    }
    module->hasInit = true;
}

int Aarch64Machine::callModule(shared_ptr<MachOModule> module, string symbolName) {
    uc2instance[this->uc] = this;
    if (symbolName.length() == 0) {
        printf("[-] error: does not support call entry-point");
        assert(false);
    }
    
    Symbol *symbol = module->getSymbolByName(symbolName, true);
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
    uc_hook_add(uc, &intr_hook, UC_HOOK_INTR, (void *)uc_hookintr_callback, NULL, 1, 0);
    uc_hook_add(uc, &memexp_hook, UC_HOOK_MEM_INVALID, (void *)mem_exception_hook_callback, NULL, 1, 0);
    
    // init context
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uint64_t sp = unicorn_sp_start;
    
    /**
        set sysregs
     */
    // pthread begin
    // allocate tsdObject
    sp -= 3 * 8;
    uint64_t tsdObjectAddr = sp;
    uint64_t pthreadSelf = tsdObjectAddr;
    assert(uc_mem_write(uc, tsdObjectAddr, &pthreadSelf, 8) == UC_ERR_OK);
    uint64_t pthreadErrno = 0;
    assert(uc_mem_write(uc, tsdObjectAddr + 8, &pthreadErrno, 8) == UC_ERR_OK);
    uint64_t pthreadMigReply = 0;
    assert(uc_mem_write(uc, tsdObjectAddr + 16, &pthreadMigReply, 8) == UC_ERR_OK);
    assert(uc_reg_write(uc, UC_ARM64_REG_TPIDRRO_EL0, &tsdObjectAddr) == UC_ERR_OK);
    // pthread end
    
    // set sp
    uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
    
    // call init funcs
    for (shared_ptr<MachOModule> module : loader->modules) {
        initModule(module);
    }
    
    printf("[*] execute in engine, pc = 0x%llx\n", symbolAddr);
    uc_err err = uc_emu_start(uc, symbolAddr, 0, 0, 0);
    printf("[*] execute in engine result %s\n", uc_strerror(err));
    return 0;
}
