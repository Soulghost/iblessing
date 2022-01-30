//
//  aarch64-machine.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/9/2.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-machine.hpp"
//#include "ib_pthread.hpp"
#include "uc_debugger_utils.hpp"
#include "buffered_logger.hpp"
#include "macho-memory.hpp"
#include "pthread_types_14.h"
#include "aarch64-utils.hpp"
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include "libdispatch_defines.hpp"

#define TraceLevelNone       0
#define TraceLevelASM        1
#define TraceLevelASMComment 2

#define TraceLevel TraceLevelASMComment

using namespace std;
using namespace iblessing;

// global
static map<uc_engine *, Aarch64Machine *> uc2instance;

// create disasm handle
static csh cs_handle;

#if TraceLevel >= TraceLevelASM
static uc_hook insn_hook;
#endif

static uc_hook intr_hook, memexp_hook, memaccess_hook;

static void insn_hook_callback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    // the hook is **before execute**, redirect pc cause the execute to be cancelled
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
        
        BufferedLogger::globalLogger()->printBuffer();
        print_backtrace(uc);
        assert(false);
        return;
    }
    
    if (uc2instance[uc]->threadManager->tick()) {
        printf("[Stalker][+][Thread] a context switch has occurred\n");
        return;
    }
    
    static set<string> symbolBlackList{"__platform_strlen", "__platform_bzero", "__platform_memset", "__platform_strstr", "__platform_strcmp", "__platform_strncmp", "__platform_memmove", "_getsectiondata", "_tiny_print_region_free_list", "_malloc_zone_malloc", "_mach_vm_allocate"};
    string comments = "";
#if TraceLevel >= TraceLevelASMComment
    uint64_t targetAddr = 0;
    if (strcmp(insn->mnemonic, "br") == 0 ||
        strcmp(insn->mnemonic, "blr") == 0) {
        uint64_t regValue = 0;
        assert(uc_reg_read(uc, insn->detail->arm64.operands[0].reg, &regValue) == UC_ERR_OK);
        comments = StringUtils::format("#0x%llx", regValue);
        if (regValue == 0) {
            uc_debug_print_backtrace(uc);
            assert(false);
        }
        targetAddr = regValue;
    } else if (strcmp(insn->mnemonic, "b") == 0 ||
               strncmp(insn->mnemonic, "b.", 2) == 0 ||
               strcmp(insn->mnemonic, "bl") == 0) {
        assert(insn->detail->arm64.operands[0].type == ARM64_OP_IMM);
        targetAddr = insn->detail->arm64.operands[0].imm;
    }
    
    if (targetAddr > 0) {
        Symbol *sym = uc2instance[uc]->loader->getSymbolByAddress(targetAddr);
        if (sym && sym->name.length() > 0) {
            comments += StringUtils::format(" ; target = %s, ", sym->name.c_str());
        }
    }
    
    comments += StringUtils::format("(thread %s)", uc2instance[uc]->threadManager->currentThread()->name.c_str());
    
#endif
    
#if TraceLevel >= TraceLevelASMComment
    shared_ptr<MachOModule> module = uc2instance[uc]->loader->findModuleByAddr(address);
#else
    MachOModule *module = nullptr;
#endif
    BufferedLogger *logger = BufferedLogger::globalLogger();
    bool intraFunction = false;
    if (module) {
        static set<string> moduleBlackList{};
        if (moduleBlackList.find(module->name) == moduleBlackList.end()) {
            Symbol *sym = module->getSymbolByAddress(address);
            if (sym && sym->name.length() > 0) {
                logger->append(StringUtils::format("[Stalker] ------ callee: 0x%08llx: %s:\n", address, sym->name.c_str()));
            } else {
                sym = module->getSymbolNearByAddress(address);
                if (sym && sym->name.length() > 0) {
                    intraFunction = true;
                    comments += StringUtils::format("(in %s)", sym->name.c_str());
                }
            }
//            if (module->name != "libdyld.dylib") {
            if (!intraFunction) {
                logger->append(StringUtils::format("[Stalker] 0x%08llx %s %s ; %s (%s 0x%llx)\n", insn->address, insn->mnemonic, insn->op_str, comments.c_str(), module->name.c_str(), module->addr));
            } else if (symbolBlackList.find(sym->name) == symbolBlackList.end()) {
                logger->append(StringUtils::format("[Stalker] 0x%08llx %s %s ; %s (%s 0x%llx)\n", insn->address, insn->mnemonic, insn->op_str, comments.c_str(), module->name.c_str(), module->addr));
            }
//            }
        }
    } else {
        logger->append(StringUtils::format("[Stalker] 0x%08llx %s %s ; %s\n", insn->address, insn->mnemonic, insn->op_str, comments.c_str()));
    }
    
    if (address == 0x98004EDC4) {
        static bool hasPrintRootQueues = false;
        if (!hasPrintRootQueues) {
            hasPrintRootQueues = true;
            dispatch_queue_global_s *rootQueues = (dispatch_queue_global_s *)0x9D289CFC0;
            for (int i = 0; i < 12; i++) {
                printf("[Stalker][*][Dispatch] root queue #%d: %p, name %s\n", i, rootQueues, rootQueues->dq_label);
                rootQueues += 1;
            }
        }
        
        uint64_t dq;
        uint32_t op;
        ensure_uc_reg_read(UC_ARM64_REG_X0, &dq);
        ensure_uc_reg_read(UC_ARM64_REG_W1, &op);
        static const char *op_map[] = {
            "DISPATCH_RESUME",
            "DISPATCH_ACTIVATE",
            "DISPATCH_ACTIVATION_DONE"
        };
        
        dispatch_queue_s *queue = (dispatch_queue_s *)dq;
        printf("[Stalker][*][Dispatch] dispatch_queue_resume dq 0x%llx(name=%s, targetq %p(%s)), op %s\n", dq, queue->dq_label, queue->do_targetq, queue->do_targetq->dq_label, op_map[op]);
    }
    if (address == 0x98005B8B4) {
        uint64_t type, handler, mask, q;
        ensure_uc_reg_read(UC_ARM64_REG_X0, &type);
        ensure_uc_reg_read(UC_ARM64_REG_X1, &handler);
        ensure_uc_reg_read(UC_ARM64_REG_X2, &mask);
        ensure_uc_reg_read(UC_ARM64_REG_X3, &q);
        dispatch_queue_s *dq = (dispatch_queue_s *)q;
        const char *kind = *(const char **)type;
        printf("[Stalker][*][Dispatch] dispatch_create_source type 0x%llx(%s), handler 0x%llx, mask 0x%llx, queue 0x%llx(targetq = %p(%s))\n", type, kind, handler, mask, q, dq->do_targetq,  dq->do_targetq->dq_label);
    }
    if (address == 0x98005C220) {
        uint64_t source, handler;
        ensure_uc_reg_read(UC_ARM64_REG_X0, &source);
        ensure_uc_reg_read(UC_ARM64_REG_X1, &handler);
        printf("[Stalker][*][Dispatch] dispatch_source_set_event_handler source 0x%llx, handler 0x%llx\n", source, handler);
    }
    if (address == 0x980059354) {
        uint64_t dq;
        ensure_uc_reg_read(UC_ARM64_REG_X0, &dq);
        
        dispatch_queue_s *queue = (dispatch_queue_s *)dq;
        printf("[Stalker][*][Dispatch] dispatch_worker_thread2 process on root queue %p(%s)\n", queue, queue->dq_label);
    }
    
    free(codes);
    cs_free(insn, count);
    
    uc_debug_check_breakpoint(uc, address);
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

static bool mem_access_hook_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    return true;
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
    uint64_t pc;
    ensure_uc_reg_read(UC_ARM64_REG_PC, &pc);
    uc_debug_print_backtrace(uc);
    uc_debug_print_backtrace(uc, true);
    assert(false);
    return false;
}

void Aarch64Machine::initModule(shared_ptr<MachOModule> module) {
    initModule(module, defaultEnv);
}

void Aarch64Machine::initModule(shared_ptr<MachOModule> module, ib_module_init_env &env) {
    static set<string> blackListModule{"UIKit", "CoreGraphics", "AdSupport", "CoreTelephony"};
    if (blackListModule.find(module->name) != blackListModule.end()) {
        module->hasInit = true;
        return;
    }
    
    if (module->hasInit) {
        return;
    }
    printf("[+] init module %s\n", module->name.c_str());
    // FIXME: vars, envs
    printf("  [+] process routines\n");
    for (MachORoutine &routine: module->routines) {
        uint64_t addr = routine.addr;
        printf("  [*] execute routine in engine, pc = 0x%llx\n", addr);
        uc_callFunction(uc, addr, Aarch64FunctionCallArg::voidArg(), {});
    }
    printf("  [+] process mod_init_funcs\n");
    for (MachODynamicLibrary &lib : module->dynamicLibraryDependenciesUnupward) {
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
        assert(uc_reg_write(uc, UC_ARM64_REG_X2, &env.environAddr) == UC_ERR_OK);
        // apple
        assert(uc_reg_write(uc, UC_ARM64_REG_X3, &env.appleAddr) == UC_ERR_OK);
        // vars
        assert(uc_reg_write(uc, UC_ARM64_REG_X4, &env.varsAddr) == UC_ERR_OK);
        
        assert(uc_reg_write(uc, UC_ARM64_REG_LR, &callFunctionLR) == UC_ERR_OK);
        uc_err err = uc_emu_start(uc, addr, callFunctionLR, 0, 0);
        printf("  [*] execute mod_init_func in engine result %s\n", uc_strerror(err));
        if (err != UC_ERR_OK) {
            BufferedLogger::globalLogger()->printBuffer();
            print_backtrace(uc);
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

static uint64_t createEnv(uc_engine *uc, uint64_t *sp, vector<string> envList) {
    *sp = uc_alloca(*sp, sizeof(uint64_t) * (envList.size() + 1));
    uint64_t environ = *sp;
    uint64_t null64 = 0;
    uint64_t environ_cursor = environ;
    for (string &env : envList) {
        *sp = uc_alloca(*sp, env.length() + 1);
        assert(uc_mem_write(uc, *sp, env.c_str(), env.length()) == UC_ERR_OK);
        assert(uc_mem_write(uc, *sp + env.length(), &null64, 1) == UC_ERR_OK);
        assert(uc_mem_write(uc, environ_cursor, sp, sizeof(uint64_t)) == UC_ERR_OK);
        environ_cursor += sizeof(uint64_t);
    }
    assert(uc_mem_write(uc, environ_cursor, &null64, sizeof(uint64_t)) == UC_ERR_OK);
    return environ;
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
#if TraceLevel >= TraceLevelASM
    uc_hook_add(uc, &insn_hook, UC_HOOK_CODE, (void *)insn_hook_callback, NULL, 1, 0);
#endif
    uc_hook_add(uc, &intr_hook, UC_HOOK_INTR, (void *)uc_hookintr_callback, NULL, 1, 0);
    uc_hook_add(uc, &memexp_hook, UC_HOOK_MEM_INVALID, (void *)mem_exception_hook_callback, NULL, 1, 0);
    uc_hook_add(uc, &memaccess_hook, UC_HOOK_MEM_WRITE, (void *)mem_access_hook_callback, NULL, 1, 0);
    // init context
    //uint64_t unicorn_sp_start = UnicornStackTopAddr;
    // BXL modification: share stack between host and guest
    uint64_t unicorn_sp_start = loader->memoryManager->stackNew();
    uint64_t sp = unicorn_sp_start;
    
    // setup common text
    uint32_t nopCode = 0xd503201f;
    
    // nop lr page
    uint64_t nopPageAddr = (uint64_t)loader->memoryManager->mmapSharedMem(0x600000000, 0x4000, UC_PROT_ALL);
    callFunctionLR = nopPageAddr;
    ensure_uc_mem_write(callFunctionLR, &nopCode, sizeof(uint32_t));
    nopPageAddr += sizeof(uint32_t);
    
    redirectFunctionLR = nopPageAddr;
    ensure_uc_mem_write(redirectFunctionLR, &nopCode, sizeof(uint32_t));
    nopPageAddr += sizeof(uint32_t);
    ensure_uc_mem_write(nopPageAddr, &nopCode, sizeof(uint32_t));
    nopPageAddr += sizeof(uint32_t);
    ensure_uc_mem_write(nopPageAddr, &nopCode, sizeof(uint32_t));
    nopPageAddr += sizeof(uint32_t);
    
    uint64_t loopCode = 0xd4200020;
    ensure_uc_mem_write(nopPageAddr, &loopCode, sizeof(uint32_t));
    
    // FATAL FIXME: tricky nop
    uint64_t nop_xpc_release_in_libxpc_initializer_addr = 0x1C8947D34 + DYLD_FIXED_SLIDE;
    ensure_uc_mem_write(nop_xpc_release_in_libxpc_initializer_addr, &nopCode, sizeof(uint32_t));
    {
        // kstool arm64 "b 0x1AEDBD8A4" 0x1AEDBD824
//        uint32_t patchB = 0x14000020;
//        ensure_uc_mem_write(0x1AEDBD824, &patchB, sizeof(uint32_t));
    }

    /**
        setup vars
     */
    // env
    // environ
    uint64_t null64 = 0;
    uint64_t environ = createEnv(uc, &sp, {"MallocCorruptionAbort=0", "PTHREAD_PTR_MUNGE_TOKEN=0x1"});
    
    // _NSGetEnviron
    sp = uc_alloca(sp, sizeof(uint64_t));
    uint64_t _NSGetEnv = sp;
    assert(uc_mem_write(uc, _NSGetEnv, &environ, sizeof(uint64_t)) == UC_ERR_OK);
    
    // ProgramName
    const char *programName = module->name.c_str();
    sp = uc_alloca(sp, strlen(programName) + 1);
    uint64_t programNameAddr = sp;
    assert(uc_mem_write(uc, programNameAddr, programName, strlen(programName)) == UC_ERR_OK);
    assert(uc_mem_write(uc, programNameAddr + strlen(programName), &null64, 1) == UC_ERR_OK);
    
    sp = uc_alloca(sp, 8);
    uint64_t programNamePtr = sp;
    ensure_uc_mem_write(programNamePtr, &programNameAddr, 8);
    
    // _NSGetArgc
    sp = uc_alloca(sp, sizeof(uint64_t));
    uint64_t _NSGetArgc = sp;
    uint64_t argcVal = 1;
    assert(uc_mem_write(uc, _NSGetArgc, &argcVal, sizeof(uint64_t)) == UC_ERR_OK);
    
    // _NSGetArgv
    sp = uc_alloca(sp, sizeof(uint64_t));
    uint64_t _NSGetArgv = sp;
    assert(uc_mem_write(uc, _NSGetArgv, &programNamePtr, sizeof(uint64_t)) == UC_ERR_OK);
    
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
    shared_ptr<PthreadKern> threadManager = make_shared<PthreadKern>();
    this->threadManager = threadManager;
    threadManager->machine = this->shared_from_this();
    shared_ptr<PthreadInternal> mainThread = make_shared<PthreadInternal>();
    mainThread->isMain = true;
    mainThread->ticks = 0;
    mainThread->maxTikcs = 1000;
    mainThread->name = "main";
    threadManager->createThread(mainThread);
    threadManager->setActiveThread(mainThread);
    threadManager->setInterruptEnable(true);
    
    // pthread begin
    uint64_t pthreadSize = sizeof(ib_pthread_s);
    // alloca
    sp = uc_alloca(sp, pthreadSize);
    uint64_t pthreadAddr = sp;
    uint64_t pthreadTSD = pthreadAddr + __offsetof(ib_pthread_s, tsd);
    
    // init
    ib_pthread_s *thread = (ib_pthread_s *)calloc(1, pthreadSize);
    *((uint64_t *)&thread->tsd[0]) = pthreadAddr; // self
    thread->tsd[1] = 0; // errno
    thread->tsd[2] = 0;
    *((uint64_t *)&thread->tsd[3]) = 0xaa; // kport
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
    
    // apple args
    uint64_t appleAddr = createEnv(uc, &sp, {"malloc_entropy=0x0,0x0"});
    
    // set sp
    uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
    
    // call init funcs
    ib_module_init_env initEnv;
    initEnv.environAddr = environ;
    initEnv.varsAddr = varsAddr;
    initEnv.appleAddr = appleAddr;
    
    // setup libSystem kerneltrace page
    uint64_t kernel_common_page_addr = IB_KERNEL_BASE64;
    uint64_t kernel_common_page_size = 0x10000;
    assert(uc_mem_map(uc, kernel_common_page_addr, kernel_common_page_size, UC_PROT_READ) == UC_ERR_OK);
    {
        void *nullchunk = calloc(1, kernel_common_page_size);
        ensure_uc_mem_write(kernel_common_page_addr, nullchunk, kernel_common_page_size);
    }
    
    
    // setup kern common pages
    uint64_t cpuCount = 1;
    assert(uc_mem_write(uc, IB_COMM_PAGE_NCPUS, &cpuCount, 1) == UC_ERR_OK);
    assert(uc_mem_write(uc, IB_COMM_PAGE_ACTIVE_CPUS, &cpuCount, 1) == UC_ERR_OK);
    assert(uc_mem_write(uc, IB_COMM_PAGE_PHYSICAL_CPUS, &cpuCount, 1) == UC_ERR_OK);
    assert(uc_mem_write(uc, IB_COMM_PAGE_LOGICAL_CPUS, &cpuCount, 1) == UC_ERR_OK);
    assert(uc_mem_write(uc, IB_COMM_PAGE_MEMORY_SIZE, &null64, 8) == UC_ERR_OK);
    
    uint64_t pageShift = 14;
    ensure_uc_mem_write(IB_COMM_PAGE_USER_PAGE_SHIFT_64, &pageShift, 8);
    ensure_uc_mem_write(IB_COMM_PAGE_KERNEL_PAGE_SHIFT, &pageShift, 8);
//    static set<string> moduleInitBlackList{"CoreFoundation", "Foundation"};
//    if (moduleInitBlackList.find(module->name) != moduleInitBlackList.end()) {
//        printf("[Stalker][!][Warn] skip mod init for %s\n", module->name.c_str());
//        module->hasInit = true;
//        continue;
//    }
    // init log function
//    shared_ptr<MachOModule> foundationModule = loader->findModuleByName("Foundation");
//    Symbol *_NSSetLogCStringFunction = foundationModule->getSymbolByName("__NSSetLogCStringFunction", false);
//    uint64_t _NSSetLogCStringFunction_addr = _NSSetLogCStringFunction->info->n_value;
//    uc_callFunction(uc, _NSSetLogCStringFunction_addr, Aarch64FunctionCallArg::voidArg(), {0x0});
    
    // init dyld lookup
    // _setLookupFunc
    // void __fastcall _xpc_bundle_resolve(_/Users/soulghost/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/2.0b4.0.9/a059f2c5177212c13d02987f45ab4e54/Message/MessageTemp/4ebc709cee4f193faf94a726391c292d/Image/137581642838792_.pic.jpg_int64 a1)
    // xpc_bundle_t xpc_bundle_create(const char *path, int /* XPC_BUNDLE_FROM_PATH = 0x1? */);
    // xpc_bundle_resolve_sync -> _xpc_bundle_resolve_sync
    uc_debug_set_breakpoint(uc, 0x9C893C3C8, "send result");
    uc_debug_set_breakpoint(uc, 0x980060F08, "dispatch_mach_receive_barrier_f_VARIANT_mp prologue");
//    uc_debug_set_breakpoint(uc, 0x9C891D4F4, "first calculate priority");
//    uc_debug_set_breakpoint(uc, 0x980059340, "calc priority");
//    uc_debug_set_breakpoint(uc, 0x9C893BB18, "call to dispatch_mach_connect");
//    uc_debug_set_breakpoint(uc, 0x98004F1E4, "dispatch_lane_resume_activate");
//    uc_debug_set_breakpoint(uc, 0x98004EE60, "call to dispatch_lane_resume_activate");
//    uc_debug_set_breakpoint(uc, 0x980049B70, "call to dispatch_objc_activate");
//    uc_debug_set_breakpoint(uc, 0x980049B50, "dispatch work select");
//    uc_debug_set_breakpoint(uc, 0x980061218, "dispatch_mach_activate_VARIANT_mp after prologue");
//    uc_debug_set_breakpoint(uc, 0x98005F4E0, "dispatch_mach_send_and_wait_for_reply:130 mach_msg");
//    uc_debug_set_breakpoint(uc, 0x98005F684, "dispatch_mach_send_and_wait_for_reply:204 (_DWORD)v67 != msgh_local_port && (msgh_local_port + 1 > 1 || v44)");
//    uc_debug_set_breakpoint(uc, 0x9C8941F24, "xpc_dictionary_apply(xpc_object_t xdict, xpc_dictionary_applier_t applier)");
//    uc_debug_set_breakpoint(uc, 0x9C8941FA0, "xpc_dictionary_apply_node_f");
//    uc_debug_set_breakpoint(uc, 0x9C891D560, "libdispatch_workerfunction"); 
//    uc_debug_set_breakpoint(uc, 0x9C891D4AC, "pthread_wqthread prologue");
//    uc_debug_set_breakpoint(uc, 0x98005932C, "dispatch_worker_thread2 clz");
//    uc_debug_set_breakpoint(uc, 0x980059324, "dispatch_worker_thread2, calculate qos");
//    uc_debug_set_breakpoint(uc, 0x9800A59D4, "dispatch_get_global_queue prologue");
//    uc_debug_set_breakpoint(uc, 0x9800A5A60, "dispatch_get_global_queue qos");
//    uc_debug_set_breakpoint(uc, 0x9C891D548); // _pthread_wqthread pthread_priority
//    uc_debug_set_breakpoint(uc, 0x9C891E578);
//    uc_debug_set_breakpoint(uc, 0x9C891E608);
//    uc_debug_set_breakpoint(uc, 0x9941F1B50);
//    uc_debug_set_breakpoint(uc, 0x994202428);
//    uc_debug_set_breakpoint(uc, 0x1800666B8); // event loop
//    uc_debug_set_breakpoint(uc, 0x18004D3BC); // dispatch_after
//    uc_debug_set_breakpoint(uc, 0x1800593C0); // dispatch_kevent_worker_thread
//    uc_debug_set_breakpoint(uc, 0x1000079b0);
//    uc_debug_set_breakpoint(uc, 0x1000079b4);
//    uc_debug_set_breakpoint(uc, 0x1C8952F3C);
//    uc_debug_set_breakpoint(uc, 0x1C8952E90);
//    uc_debug_set_breakpoint(uc, 0x1C8952CE4);
//    uc_debug_set_breakpoint(uc, 0x1C8952A9C); // fstat(plist_path)
//    uc_debug_set_breakpoint(uc, 0x1C8952C80);
//    uc_debug_set_breakpoint(uc, 0x1C8952CD8);
//    uc_debug_set_breakpoint(uc, 0x1941EFC60);
        //  -> 0x98004d3a4 ->
    // _dyld_initializer_0
//    uc_debug_set_breakpoint(uc, 0x1C8947D34);
    
//    shared_ptr<MachOModule> dyldModule = loader->findModuleByName("libdyld.dylib");
//    assert(dyldModule != nullptr);
//    Symbol *_setLookupFunc = dyldModule->getSymbolByName("_dyld_func_lookup", false);
//    uint64_t lookupFuncAddr = 0x233;
//    callFunction(uc, _setLookupFunc->info->n_value, Aarch64FunctionCallArg::voidArg(), {lookupFuncAddr});
    
    // init modules
    defaultEnv = initEnv;
    for (shared_ptr<MachOModule> module : loader->modules) {
        initModule(module, initEnv);
    }
    
    // fake a stop addr
    assert(uc_reg_write(uc, UC_ARM64_REG_LR, &callFunctionLR) == UC_ERR_OK);
    printf("[*] execute in engine, pc = 0x%llx\n", symbolAddr);
    uc_err err = uc_emu_start(uc, symbolAddr, callFunctionLR, 0, 0);
    BufferedLogger::globalLogger()->printBuffer();
    printf("[*] execute in engine result %s\n", uc_strerror(err));
    assert(err == UC_ERR_OK);
    return 0;
}

void Aarch64Machine::setErrno(int no) {
    if (errnoAddr > 0) {
        ensure_uc_mem_write(errnoAddr, &no, sizeof(int));
    }
}

void Aarch64Machine::setErrnoAddr(uint64_t addr) {
    errnoAddr = addr;
    setErrno(0);
}
