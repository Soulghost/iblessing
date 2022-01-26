//
//  dyld2.cpp
//  dyld2
//
//  Created by Soulghost on 2021/11/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "dyld2.hpp"
#include <stdarg.h>
#include "macho-memory.hpp"
#include "macho-loader.hpp"
#include <memory>
#include "StringUtils.h"
#include "SymbolTable.hpp"
#include "uc_debugger_utils.hpp"
#include "aarch64-svc-manager.hpp"

using namespace std;
using namespace iblessing;

namespace dyld {

void log(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vdprintf(1, format, list);
    va_end(list);
}

void logToConsole(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vdprintf(1, format, list);
    va_end(list);
}

SharedCacheLoadInfo mapSharedCache(uc_engine *uc, uintptr_t mainExecutableSlide) {
    SharedCacheLoadInfo sSharedCacheLoadInfo;
    SharedCacheOptions opts;
    opts.cacheDirOverride    = NULL;
    opts.forcePrivate        = false;
    opts.useHaswell          = false;
    opts.verbose             = true;
    // <rdar://problem/32031197> respect -disable_aslr boot-arg
    // <rdar://problem/56299169> kern.bootargs is now blocked
    opts.disableASLR         = mainExecutableSlide == 0;
    loadDyldCache(uc, opts, &sSharedCacheLoadInfo);

    // update global state
    if ( sSharedCacheLoadInfo.loadAddress != 0 ) {

    }
    return sSharedCacheLoadInfo;
}

uint64_t dlsym_internal(shared_ptr<MachOLoader> loader, int64_t handle, uint64_t symbolAddr, uint64_t callerAddress) {
    uc_engine *uc = loader->uc;
    char *symbolName = MachoMemoryUtils::uc_read_string(uc, symbolAddr, 1000, false);
    if (handle == IB_RTLD_MAIN_ONLY) {
        if (strcmp(symbolName, "_os_debug_log_redirect_func") == 0) {
#if 0
            bool _os_debug_log_redirect_func(const char *msg);
#endif
            static uint64_t symaddr = 0;
            if (symaddr == 0) {
                symaddr = loader->svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                    uint64_t msgAddr = 0;
                    ensure_uc_reg_read(UC_ARM64_REG_X0, &msgAddr);
                    char *msg = MachoMemoryUtils::uc_read_string(uc, msgAddr, 1000, true);
                    printf("[Stalker][*][Logger] os_debug_log_redirect_func: %s\n", msg);
                    free(msg);
                });
            }
            return symaddr;
        }
        if (strcmp(symbolName, "os_crash_function") == 0) {
#if 0
            bool os_crash_function(const char *msg);
#endif
            static uint64_t symaddr = 0;
            if (symaddr == 0) {
                symaddr = loader->svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                    uint64_t msgAddr = 0;
                    ensure_uc_reg_read(UC_ARM64_REG_X0, &msgAddr);
                    char *msg = MachoMemoryUtils::uc_read_string(uc, msgAddr, 1000, true);
                    printf("[Stalker][*][Logger] _os_crash_function: %s\n", msg);
                    free(msg);
                });
            }
            return symaddr;
        }
    }
    if (strcmp(symbolName, "sandbox_check") == 0 ||
        strcmp(symbolName, "_availability_version_check") == 0 ||
        strcmp(symbolName, "dispatch_after") == 0 ||
        strcmp(symbolName, "dispatch_async") == 0) {
        uc_debug_print_backtrace(uc);
        assert(false);
    }
    
    Symbol *symbol = nullptr;
    string symName = StringUtils::format("_%s", symbolName);
    free(symbolName);
    symbolName = (char *)symName.c_str();
    if (handle > 0) {
        shared_ptr<MachOModule> module = loader->findModuleByAddr(handle);
        symbol = module->getSymbolByName(symbolName, false);
    } else {
        for (shared_ptr<MachOModule> module : loader->modules) {
            symbol = module->getSymbolByName(symbolName, false);
            if (symbol) {
                break;
            }
        }
    }
    
    if (!symbol) {
        uc_debug_print_backtrace(uc);
        assert(false);
    }
    
    uint64_t targetAddr = symbol ? symbol->info->n_value : 0;
    return targetAddr;
}

}
