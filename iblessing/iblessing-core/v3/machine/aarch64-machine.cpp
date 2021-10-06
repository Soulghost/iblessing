//
//  aarch64-machine.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/9/2.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-machine.hpp"
#include "ib_pthread.hpp"
#include "uc_debugger_utils.hpp"
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/vendor/capstone/capstone.h>

using namespace std;
using namespace iblessing;

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
            assert(uc_reg_read(uc, UC_ARM64_REG_W9, &w9) == UC_ERR_OK);
            comments = StringUtils::format("w9 = %d", w9);
        } else if (address == 0x100E3A89C) {
            int w20;
            assert(uc_reg_read(uc, UC_ARM64_REG_W20, &w20) == UC_ERR_OK);
            comments = StringUtils::format("w20 = %d", w20);
        } else if (address == 0x100E3A878) {
            int w9;
            assert(uc_reg_read(uc, UC_ARM64_REG_W9, &w9) == UC_ERR_OK);
            comments = StringUtils::format("w9 = %d(0x%x)", w9, w9);
        } else if (address == 0x100E3C4EC) {
            int w8;
            assert(uc_reg_read(uc, UC_ARM64_REG_W8, &w8) == UC_ERR_OK);
            comments = StringUtils::format("w8 = %d", w8);
        } else if (address == 0x100F4335C) {
            uint64_t x0, x1, x2, sp;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &x0) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X1, &x1) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X2, &x2) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_SP, &sp) == UC_ERR_OK);
            comments = StringUtils::format("x0 = 0x%llx, x1 = 0x%llx, x2 = 0x%llx, sp = 0x%llx", x0, x1, x2, sp);
        } else if (address == 0x100E3A6DC) {
            uint64_t x0, x1, x2, sp;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &x0) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X1, &x1) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X2, &x2) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_SP, &sp) == UC_ERR_OK);
            comments = StringUtils::format("x0 = 0x%llx, x1 = 0x%llx, x2 = 0x%llx, sp = 0x%llx", x0, x1, x2, sp);
        } else if (address == 0x100F4332C) {
            uint64_t x0, x1, x2, sp;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &x0) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X1, &x1) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X2, &x2) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_SP, &sp) == UC_ERR_OK);
            comments = StringUtils::format("x0 = 0x%llx, x1 = 0x%llx, x2 = 0x%llx, sp = 0x%llx", x0, x1, x2, sp);
        } else if (address == 0x100bfbbb4) {
            uint64_t x0;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &x0) == UC_ERR_OK);
            comments = StringUtils::format("x0 = 0x%llx", x0);
        } else if (address == 0x100D41940) {
            uint64_t x20;
            assert(uc_reg_read(uc, UC_ARM64_REG_X20, &x20) == UC_ERR_OK);
            comments = StringUtils::format("x20 = 0x%llx", x20);
        } else if (address == 0x100D41914) {
            uint64_t w19;
            assert(uc_reg_read(uc, UC_ARM64_REG_W19, &w19) == UC_ERR_OK);
            comments = StringUtils::format("w19 = 0x%llx", w19);
        } else if (address == 0x100D41910) {
            uint64_t w0;
            assert(uc_reg_read(uc, UC_ARM64_REG_W0, &w0) == UC_ERR_OK);
            comments = StringUtils::format("w0 = 0x%llx", w0);
        } else if (address == 0x100419790) {
            uint64_t x0;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &x0) == UC_ERR_OK);
            comments = StringUtils::format("x0 = 0x%llx", x0);
        } else if (address == 0x100E3ED9C) {
            uint64_t x8;
            assert(uc_reg_read(uc, UC_ARM64_REG_X8, &x8) == UC_ERR_OK);
            comments = StringUtils::format("x8 = 0x%llx", x8);
        } else if (address == 0x100F31250) {
            uint64_t x8;
            assert(uc_reg_read(uc, UC_ARM64_REG_X8, &x8) == UC_ERR_OK);
            comments = StringUtils::format("x8 = 0x%llx", x8);
        } else if (address == 0x100eb539c) {
            uint64_t x8;
            assert(uc_reg_read(uc, UC_ARM64_REG_X8, &x8) == UC_ERR_OK);
            comments = StringUtils::format("x8 = 0x%llx", x8);
        } else if (address == 0x100eb531c) {
            uint64_t x0;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &x0) == UC_ERR_OK);
            comments = StringUtils::format("x0 = 0x%llx", x0);
        } else if (address == 0x100EB5338) {
            uint64_t x19;
            assert(uc_reg_read(uc, UC_ARM64_REG_X19, &x19) == UC_ERR_OK);
            comments = StringUtils::format("x19 = 0x%llx", x19);
        } else if (address == 0x100EB53A4) {
            uint64_t x8, x19;
            assert(uc_reg_read(uc, UC_ARM64_REG_X8, &x8) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X19, &x19) == UC_ERR_OK);
            comments = StringUtils::format("x8 = 0x%llx, x19 = 0x%llx", x8, x19);
        }
    }
    
    shared_ptr<MachOModule> module = uc2instance[uc]->loader->findModuleByAddr(address);
    if (module) {
        if (module->name != "libdyld.dylib") {
            printf("[Stalker] 0x%08llx %s %s ; %s (%s 0x%llx)\n", insn->address, insn->mnemonic, insn->op_str, comments.c_str(), module->name.c_str(), module->addr);
        }
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
//    if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_WRITE_UNMAPPED) {
//#define UC_PAGE_SIZE 0x1000
//        uint64_t page_begin = address & ~(UC_PAGE_SIZE - 1);
//        uc_mem_map(uc, page_begin, UC_PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE);
//        
//        // FIXME: fill zero
//        void *dummy_bytes = calloc(1, size);
//        uc_mem_write(uc, address, dummy_bytes, size);
//        return true;
//    } else if (type == UC_MEM_FETCH_UNMAPPED) {
//        // FIXME: pthread [Stalker] 0x100f38410 mrs x8, tpidrro_el0 ;
//        // see unidbg-ios/src/main/java/com/github/unidbg/ios/MachOLoader.java initializeTSD
////        printf("Warn: [-] unmapped instruction at 0x%llx\n", address);
//        assert(false);
//    }
    assert(false);
    return false;
}

void Aarch64Machine::initModule(shared_ptr<MachOModule> module, ib_module_init_env &env) {
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
        initModule(dependModule, env);
    }
    
    // FIXME: vars
    for (MachOModInitFunc &initFunc : module->modInitFuncs) {
        uint64_t addr = initFunc.addr;
        printf("  [*] execute mod_init_func in engine, pc = 0x%llx\n", addr);
        // FIXME: set mach_header
        // argc
        uint64_t nullval = 0;
        assert(uc_reg_write(uc, UC_ARM64_REG_X0, &nullval) == UC_ERR_OK);
        // argv
        assert(uc_reg_write(uc, UC_ARM64_REG_X1, &nullval) == UC_ERR_OK);
        // envp
        assert(uc_reg_write(uc, UC_ARM64_REG_X2, &nullval) == UC_ERR_OK);
        // apple
        assert(uc_reg_write(uc, UC_ARM64_REG_X3, &nullval) == UC_ERR_OK);
        // vars
        assert(uc_reg_write(uc, UC_ARM64_REG_X4, &env.varsAddr) == UC_ERR_OK);
        
        uc_err err = uc_emu_start(uc, addr, 0, 0, 0);
        printf("  [*] execute mod_init_func in engine result %s\n", uc_strerror(err));
        if (err != UC_ERR_OK) {
            print_uc_mem_regions(uc);
            assert(false);
        }
    }
    module->hasInit = true;
}

static uint64_t uc_alloca(uint64_t sp, uint64_t size) {
    sp -= size;
    sp &= (~15);
    return sp;
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
        setup vars
     */
    // env
    // environ
    vector<string> envList = {"MallocCorruptionAbort=0"};
    sp = uc_alloca(sp, sizeof(uint64_t) * (envList.size() + 1));
    uint64_t environ = sp;
    
    uint64_t null64 = 0;
    uint64_t environ_cursor = environ;
    for (string &env : envList) {
        sp = uc_alloca(sp, env.length() + 1);
        assert(uc_mem_write(uc, sp, env.c_str(), env.length()) == UC_ERR_OK);
        assert(uc_mem_write(uc, sp + env.length(), &null64, 1) == UC_ERR_OK);
        assert(uc_mem_write(uc, environ_cursor, &sp, sizeof(uint64_t)) == UC_ERR_OK);
        environ_cursor += sizeof(uint64_t);
    }
    assert(uc_mem_write(uc, environ_cursor, &null64, sizeof(uint64_t)) == UC_ERR_OK);
    
    // _NSGetEnviron
    sp = uc_alloca(sp, sizeof(uint64_t));
    uint64_t _NSGetEnv = sp;
    assert(uc_mem_write(uc, _NSGetEnv, &environ, sizeof(uint64_t)) == UC_ERR_OK);
    
    // ProgramName
    const char *programName = module->name.c_str();
    sp = uc_alloca(sp, strlen(programName) + 1);
    uint64_t programNamePtr = sp;
    assert(uc_mem_write(uc, programNamePtr, &programName, strlen(programName)) == UC_ERR_OK);
    assert(uc_mem_write(uc, programNamePtr + strlen(programName), &null64, 1) == UC_ERR_OK);
    
    // _NSGetArgc
    sp = uc_alloca(sp, sizeof(uint64_t));
    uint64_t _NSGetArgc = sp;
    uint64_t argcVal = 1;
    assert(uc_mem_write(uc, _NSGetArgc, &argcVal, sizeof(uint64_t)) == UC_ERR_OK);
    
    // _NSGetArgv
    sp = uc_alloca(sp, sizeof(uint64_t));
    uint64_t _NSGetArgv = sp;
    assert(uc_mem_write(uc, _NSGetArgv, &null64, sizeof(uint64_t)) == UC_ERR_OK);
    
    // vars
    uint64_t varsSize = 5 * sizeof(uint64_t);
    sp = uc_alloca(sp, varsSize);
    uint64_t varsAddr = sp;
    printf("[Stalker][+] varsAddr at 0x%llx\n", varsAddr);
    assert(uc_mem_write(uc, varsAddr, &module->machHeader, sizeof(uint64_t)) == UC_ERR_OK);
    assert(uc_mem_write(uc, varsAddr + sizeof(uint64_t), &_NSGetArgc, sizeof(uint64_t)) == UC_ERR_OK);
    assert(uc_mem_write(uc, varsAddr + 2 * sizeof(uint64_t), &_NSGetArgv, sizeof(uint64_t)) == UC_ERR_OK);
    assert(uc_mem_write(uc, varsAddr + 3 * sizeof(uint64_t), &_NSGetEnv, sizeof(uint64_t)) == UC_ERR_OK);
    assert(uc_mem_write(uc, varsAddr + 4 * sizeof(uint64_t), &programNamePtr, sizeof(uint64_t)) == UC_ERR_OK);
    /**
        set sysregs
     */
    // pthread begin
    uint64_t pthreadSize = sizeof(ib_pthread);
    // alloca
    sp = uc_alloca(sp, pthreadSize);
    uint64_t pthreadAddr = sp;
    uint64_t pthreadTSD = pthreadAddr + __offsetof(ib_pthread, self);
    
    // init
    ib_pthread *thread = (ib_pthread *)calloc(1, pthreadSize);
    thread->self = pthreadAddr;
    thread->err_no = 0;
    thread->mig_reply = 0;
    assert(uc_mem_write(uc, pthreadAddr, (void *)thread, pthreadSize) == UC_ERR_OK);
    assert(uc_reg_write(uc, UC_ARM64_REG_TPIDRRO_EL0, &pthreadTSD) == UC_ERR_OK);
    free(thread);
    
    // allocate tsdObject
//    sp -= 3 * 8;
//    uint64_t tsdObjectAddr = sp;
//    uint64_t pthreadSelf = tsdObjectAddr;
//    assert(uc_mem_write(uc, tsdObjectAddr, &pthreadSelf, 8) == UC_ERR_OK);
//    uint64_t pthreadErrno = 0;
//    assert(uc_mem_write(uc, tsdObjectAddr + 8, &pthreadErrno, 8) == UC_ERR_OK);
//    uint64_t pthreadMigReply = 0;
//    assert(uc_mem_write(uc, tsdObjectAddr + 16, &pthreadMigReply, 8) == UC_ERR_OK);
//    assert(uc_reg_write(uc, UC_ARM64_REG_TPIDRRO_EL0, &tsdObjectAddr) == UC_ERR_OK);
    // pthread end
    
    // set sp
    uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
    
    // call init funcs
    ib_module_init_env initEnv;
    initEnv.varsAddr = varsAddr;
    
    // setup kern common pages
    assert(uc_mem_map(uc, IB_KERNEL_BASE64, 0x10000, UC_PROT_READ) == UC_ERR_OK);
    uint64_t cpuCount = 1;
    assert(uc_mem_write(uc, IB_COMM_PAGE_NCPUS, &cpuCount, 1) == UC_ERR_OK);
    assert(uc_mem_write(uc, IB_COMM_PAGE_ACTIVE_CPUS, &cpuCount, 1) == UC_ERR_OK);
    assert(uc_mem_write(uc, IB_COMM_PAGE_PHYSICAL_CPUS, &cpuCount, 1) == UC_ERR_OK);
    assert(uc_mem_write(uc, IB_COMM_PAGE_LOGICAL_CPUS, &cpuCount, 1) == UC_ERR_OK);
    assert(uc_mem_write(uc, IB_COMM_PAGE_MEMORY_SIZE, &null64, 8) == UC_ERR_OK);
//    static set<string> moduleInitBlackList{"CoreFoundation", "Foundation"};
//    if (moduleInitBlackList.find(module->name) != moduleInitBlackList.end()) {
//        printf("[Stalker][!][Warn] skip mod init for %s\n", module->name.c_str());
//        module->hasInit = true;
//        continue;
//    }
    for (shared_ptr<MachOModule> module : loader->modules) {
        initModule(module, initEnv);
    }
    
    printf("[*] execute in engine, pc = 0x%llx\n", symbolAddr);
    uc_err err = uc_emu_start(uc, symbolAddr, 0, 0, 0);
    printf("[*] execute in engine result %s\n", uc_strerror(err));
    return 0;
}
