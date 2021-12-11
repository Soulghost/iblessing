//
//  macho-loader.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/8/26.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "macho-loader.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/dyld/dyld.hpp>
#include "StringUtils.h"
#include "ScannerContext.hpp"
#include "macho-memory.hpp"
#include "DyldSimulator.hpp"
#include <mach-o/loader.h>
#include <set>

#ifdef IB_PLATFORM_DARWIN
#include <filesystem>
#else
#include <experimental/filesystem>
#endif

#include <iblessing-core/v2/vendor/keystone/keystone.h>
#include "uc_debugger_utils.hpp"
#include "dyld2.hpp"
#include "aarch64-machine.hpp"
#include "dyld_images.h"
#include "aarch64-utils.hpp"

#ifdef IB_PLATFORM_DARWIN
namespace fs = std::filesystem;
#else
namespace fs = std::experimental::filesystem;
#endif

using namespace std;
using namespace iblessing;

static string resolveLibraryPath(string &name) {
    return name;
    // FIXME: @rpath
    string path;
    if (name.rfind("libc++") != string::npos) {
        StringUtils::replace(name, "libc++", "libcpp");
    }
    
    static const char *versions[] = { "A", "B", "C" };
    for (int i = 0; i < sizeof(versions) / sizeof(const char *); i++) {
        std::string versionPart = StringUtils::format("Versions/%s/", versions[i]);
        if (name.rfind(versionPart) != string::npos) {
            StringUtils::replace(name, versionPart, "");
        }
    }
    std::string libRoot = "/Users/soulghost/Desktop/git/iblessing/iblessing/resource/Frameworks/7.1";
    if (StringUtils::has_prefix(name, "/System/Library/Frameworks/") ||
        StringUtils::has_prefix(name, "/System/Library/PrivateFrameworks/")) {
        path = libRoot + name;
    } else if (StringUtils::has_prefix(name, "/usr/lib/")) {
        // FIXME: check file exists
        path = libRoot + name;
    }
    
    if (!filesystem::exists(path)) {
        cout << termcolor::yellow << "[-] MachOLoader - Warn: missing library " << name;
        cout << termcolor::reset << endl;
        return "";
    }
    return path;
}

MachOLoader::MachOLoader()  {
    loaderOffset = 0;
    
    workDirManager = new ScannerWorkDirManager("/tmp/iblessing-workdir");
    if (workDirManager->resetWorkDir() != 0) {
        assert(false);
    }
    
    // uc
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &this->uc);
    if (err) {
        cout << termcolor::red << "[-] MachOLoader - Error: unicorn error " << uc_strerror(err);
        cout << termcolor::reset << endl;
        assert(false);
    }
    // mach-o mapping start from 0x100000000 (app), 0x0 (dylib)
    // heap using vm_base ~ vmbase + 12G
    // stack using vmbase + 12G ~ .
    uint64_t unicorn_vm_size = 0x60000000;
    uint64_t unicorn_pagezero_size = 0x100000000;
    uint64_t unicorn_vm_start = unicorn_pagezero_size;
    err = uc_mem_map(uc, 0, unicorn_pagezero_size, UC_PROT_NONE);
    
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] MachOLoader - Error: unicorn error " << uc_strerror(err);
        cout << termcolor::reset << endl;
        assert(false);
    }
    err = uc_mem_map(uc, unicorn_vm_start, unicorn_vm_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] MachOLoader - Error: unicorn error " << uc_strerror(err);
        cout << termcolor::reset << endl;
        assert(false);
    }
    
    uint64_t stack_top = UnicornStackTopAddr;
    uint64_t stack_size = 0x10000;
    uint64_t stack_addr = stack_top - stack_size;
    err = uc_mem_map(uc, stack_addr, stack_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] MachOLoader - Error: unicorn error " << uc_strerror(err);
        cout << termcolor::reset << endl;
        assert(false);
    }
    
    // memory
    shared_ptr<MachOMemoryManager> memoryManager = make_shared<MachOMemoryManager>(uc);
    this->memoryManager = memoryManager;
    
    // svc
    shared_ptr<Aarch64SVCManager> svcManager = make_shared<Aarch64SVCManager>(uc, 0x700000000, 8 * 0xff00, 233);
    // FIXME: bxl change this to svc proxy
//    shared_ptr<Aarch64SVCManager> svcManager = make_shared<Aarch64SVCProxy>(uc, 0x700000000, 8 * 0xff00, 233, memoryManager);
    this->svcManager = svcManager;
}

MachOLoader::~MachOLoader() {
    delete workDirManager;
}

shared_ptr<MachOModule> MachOLoader::loadModuleFromFile(std::string filePath) {
    _defaultLoader = this->shared_from_this();
//    assert(modules.size() == 0);
    
    SharedCacheLoadInfo sharedCacheLoadInfo = dyld::mapSharedCache(uc, 0);
    DyldLinkContext linkContext;
    linkContext.uc = uc;
    linkContext.loadInfo = sharedCacheLoadInfo;
    this->linkContext = linkContext;
    
    shared_ptr<MachOModule> mainModule = _loadModuleFromFile(linkContext, filePath, true);
    // rebase
    printImageList();
    
    set<pair<string, string>> symbolNotFoundErrorSet;
    bool isExecutable = true;
    for (shared_ptr<MachOModule> module : modules) {
        if (isExecutable) {
            DyldSimulator::eachBind(module->mappedBuffer, module->segmentHeaders, module->dyldInfoCommand, [&](uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, int libraryOrdinal, const char *msg) {
                Dyld::bindAt(module, this->shared_from_this(), libraryOrdinal, symbolName, addr, addend, type);
            });
            isExecutable = false;
        } else {
            DyldSimulator::eachBind(linkContext, module->linkedit_base, module->segmentHeaders, module->dyldInfoCommand, [&](uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, int libraryOrdinal, const char *msg) {
                Dyld::bindAt(module, this->shared_from_this(), libraryOrdinal, symbolName, addr, addend, type);
            });
        }
    }

    // sharedcache FIXME: setLookupFunction
    static uint64_t _dyld_nopAddr = 0;
    static uint64_t _dyld_fast_stub_entryAddr = 0;
    static uint64_t _dyld_register_thread_helpersAddr = 0;
    static uint64_t _dyld_get_image_slide = 0;
    static uint64_t _dyld_register_func_for_remove_image = 0;
    static uint64_t _dyld_register_image_state_change_handler = 0;
    static uint64_t _dyld_image_path_containing_address = 0;
    static uint64_t _dyld_dlopen_address = 0;
    static uint64_t _dyld_NSGetExecutablePath_address = 0;
    static uint64_t _dyld_dlsym_address = 0;
    if (_dyld_fast_stub_entryAddr == 0) {
        Dyld::bindHooks["_abort"] = [&](string symbolName, uint64_t symbolAddr) {
            static uint64_t _abortAddr = 0;
            if (_abortAddr == 0) {
                _abortAddr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                    cout << termcolor::red << "[-] Error: abort raised !!!";
                    cout << termcolor::reset << endl;
                    assert(false);
                });
            }
            return _abortAddr;
        };
        
        // FIXME: ignore libxpc init
//                    Dyld::bindHooks["__libxpc_initializer"] = [&](string symbolName, uint64_t symbolAddr) {
//                        static uint64_t symaddr = 0;
//                        if (symaddr == 0) {
//                            symaddr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
//                                int w0 = 0;
//                                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &w0) == UC_ERR_OK);
//                            });
//                        }
//                        return symaddr;
//                    };
        
        _dyld_fast_stub_entryAddr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            uint64_t imageCache, offset;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &imageCache) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X1, &offset) == UC_ERR_OK);
            
            shared_ptr<MachOModule> targetModule = nullptr;
            for (shared_ptr<MachOModule> module : modules) {
                uint64_t begin = module->addr;
                uint64_t end = module->addr + module->size;
                if (imageCache >= begin && imageCache < end) {
                    targetModule = module;
                    break;
                }
            }
            assert(targetModule != nullptr);
            uint64_t targetAddr = Dyld::doFastLazyBind(targetModule, shared_from_this(), offset);
            
            // write return value to x0
            assert(uc_reg_write(uc, UC_ARM64_REG_X0, &targetAddr) == UC_ERR_OK);
        });
    }
    if (_dyld_nopAddr == 0) {
        _dyld_nopAddr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            printf("[Stalker][-][Warn][dyld] dyld_nop\n");
            uint64_t ret = 0;
            assert(uc_reg_write(uc, UC_ARM64_REG_X0, &ret) == UC_ERR_OK);
        });
    }
    if (_dyld_register_thread_helpersAddr == 0) {
        _dyld_register_thread_helpersAddr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            uint64_t ptr;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &ptr) == UC_ERR_OK);
            printf("[Stalker][+][dyld] dyld_register_thread_helpers 0x%llx\n", ptr);
            uint64_t ret = 0;
            assert(uc_reg_write(uc, UC_ARM64_REG_X0, &ret) == UC_ERR_OK);
        });
    }
    if (_dyld_get_image_slide == 0) {
        _dyld_get_image_slide = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            // FIXME: dyld image slide
            uint64_t machHeaderAddr;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &machHeaderAddr) == UC_ERR_OK);
            printf("[Stalker][+][dyld] dyld_get_image_slide for machHeader 0x%llx\n", machHeaderAddr);
            uint64_t ret = 0;
            assert(uc_reg_write(uc, UC_ARM64_REG_X0, &ret) == UC_ERR_OK);
        });
    }
    if (_dyld_register_func_for_remove_image == 0) {
        _dyld_register_func_for_remove_image = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            // FIXME: dyld image slide
            uint64_t callbackAddr;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &callbackAddr) == UC_ERR_OK);
            printf("[Stalker][+][dyld] dyld_register_func_for_remove_image with callback 0x%llx\n", callbackAddr);
            uint64_t ret = 0;
            assert(uc_reg_write(uc, UC_ARM64_REG_X0, &ret) == UC_ERR_OK);
        });
    }
    if (_dyld_register_image_state_change_handler == 0) {
        // code from unidbg Dyld64.java
        int swi = svcManager->allocateSWI();
        ks_engine *ks;
        uint32_t *code = nullptr;
        size_t codelen = 0;
        size_t codeCount = 0;
        string asmText =               "sub sp, sp, #0x10\n";
        asmText +=                     "stp x29, x30, [sp]\n";
        asmText += StringUtils::format("svc #0x%x\n", swi);
        asmText +=                     "ldr x7, [sp]\n"; // x7 = handler
        asmText +=                     "add sp, sp, #0x8\n"; // manipulated stack in dyld_image_state_change_handler
        asmText +=                     "cmp x7, #0\n";
        asmText +=                     "b.eq #0x40\n"; // goto (ldr x0, [sp], pop return value)
        asmText +=                     "adr lr, #-0xf\n"; // jump to ldr x7, [sp]
        asmText +=                     "bic lr, lr, #0x1\n"; // clear bit zero

        asmText +=                     "ldr x0, [sp]\n"; // x0 = state
        asmText +=                     "add sp, sp, #0x8\n";
        asmText +=                     "ldr x1, [sp]\n"; // x1 = count
        asmText +=                     "add sp, sp, #0x8\n";
        asmText +=                     "ldr x2, [sp]\n"; // x2 = imageHeader
        asmText +=                     "add sp, sp, #0x8\n";
        asmText +=                     "br x7\n"; // call (*dyld_image_state_change_handler)(enum dyld_image_states state, uint32_t infoCount, const struct dyld_image_info info[])

        asmText +=                     "ldr x0, [sp]\n"; // x0 = return value
        asmText +=                     "add sp, sp, #0x8\n";

        asmText +=                     "ldp x29, x30, [sp]\n";
        asmText +=                     "add sp, sp, #0x10\n";
        asmText +=                     "ret";
        assert(ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks) == KS_ERR_OK);
        assert(ks_asm(ks, asmText.c_str(), 0, (unsigned char **)&code, &codelen, &codeCount) == KS_ERR_OK);
        _dyld_register_image_state_change_handler = svcManager->createSVCWithCustomCode(swi, code, codelen, [&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            int state, batch;
            uint64_t handleAddr, sp;
            assert(uc_reg_read(uc, UC_ARM64_REG_SP, &sp) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_W0, &state) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_W1, &batch) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X2, &handleAddr) == UC_ERR_OK);
            typedef struct ib_dyldImageInfo64 {
                uint64_t imageLoadAddr;
                uint64_t imageFilePathAddr;
                uint64_t imageFileModDate;
            } ib_dyldImageInfo64;
            
            size_t moduleCount = modules.size();
            size_t listSize = moduleCount * sizeof(ib_dyldImageInfo64);
            uint64_t listAddr = memoryManager->alloc(listSize);
            assert(listAddr != 0);
            uint64_t listCur = listAddr;
            uint64_t null64 = 0;
            for (shared_ptr<MachOModule> module : modules) {
                ib_dyldImageInfo64 info;
                // head
                info.imageLoadAddr = module->machHeader;
                
                // path
                info.imageFilePathAddr = memoryManager->allocPath(module->path);
                
                // modDate
                info.imageFileModDate = 0;
                
                assert(uc_mem_write(uc, listCur, &info, sizeof(ib_dyldImageInfo64)) == UC_ERR_OK);
                listCur += sizeof(ib_dyldImageInfo64);
            }
            
            uint64_t imageListAddr = 0;
            if (batch == 1) {
                // registerImageStateBatchChangeHandler
                assert(state == ib_dyld_image_state_bound);
                if (dyldBoundHandlers.find(handleAddr) == dyldBoundHandlers.end()) {
                    imageListAddr = listAddr;
                    dyldBoundHandlers.insert(handleAddr);
                } else {
                    imageListAddr = 0;
                }
            } else {
                // registerImageStateSingleChangeHandler
                if (state == ib_dyld_image_state_terminated) {
                    imageListAddr = 0;
                } else {
                    // FIXME: dyld image state handler
//                                assert(state == ib_dyld_image_state_initialized);
                    if (dyldInitHandlers.find(handleAddr) == dyldInitHandlers.end()) {
                        imageListAddr = listAddr;
                        dyldInitHandlers.insert(handleAddr);
                    } else {
                        imageListAddr = 0;
                    }
                }
            }
            
            // return value;
            sp -= 8;
            assert(uc_mem_write(uc, sp, &null64, 8) == UC_ERR_OK);
            
            // null-terminate
            sp -= 8;
            assert(uc_mem_write(uc, sp, &null64, 8) == UC_ERR_OK);
            
            if (handleAddr != 0 && imageListAddr != 0) {
                // list
                sp -= 8;
                assert(uc_mem_write(uc, sp, &imageListAddr, 8) == UC_ERR_OK);
                
                // list count
                sp -= 8;
                assert(uc_mem_write(uc, sp, &moduleCount, 8) == UC_ERR_OK);
                
                // state
                sp -= 8;
                assert(uc_mem_write(uc, sp, &state, 8) == UC_ERR_OK);
                
                // handler
                sp -= 8;
                assert(uc_mem_write(uc, sp, &handleAddr, 8) == UC_ERR_OK);
            }
            assert(uc_reg_write(uc, UC_ARM64_REG_SP, &sp) == UC_ERR_OK);
        });
        free(code);
    }
    if (_dyld_dlopen_address == 0) {
        _dyld_dlopen_address = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            uint64_t pathAddr;
            int mode;
            ensure_uc_reg_read(UC_ARM64_REG_X0, &pathAddr);
            ensure_uc_reg_read(UC_ARM64_REG_W1, &mode);
            char *path = pathAddr > 0 ? MachoMemoryUtils::uc_read_string(uc, pathAddr, 1000) : NULL;
            
            uint64_t ret;
            if (path == NULL) {
                if (mode & IB_RTLD_FIRST) {
                    ret = IB_RTLD_MAIN_ONLY;
                } else {
                    ret = IB_RTLD_DEFAULT;
                }
            } else {
                string moduleName = StringUtils::path_basename(path);
                shared_ptr<MachOModule> module = findModuleByName(moduleName);
                if (module == nullptr) {
                    string _path = string(path);
                    string realPath = resolveLibraryPath(_path);
                    module = loadModuleFromFile(realPath);
                    
                    shared_ptr<Aarch64Machine> a64Machine = this->machine.lock();
                    a64Machine->initModule(module);
                }
                ret = module->machHeader;
            }
            ensure_uc_reg_write(UC_ARM64_REG_X0, &ret);
        });
    }
    if (_dyld_image_path_containing_address == 0) {
        _dyld_image_path_containing_address = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            uint64_t addr;
            ensure_uc_reg_read(UC_ARM64_REG_X0, &addr);
            shared_ptr<MachOModule> module = findModuleByAddr(addr);
            if (!module) {
                assert(false);
            }
            
            uint64_t pathAddr = memoryManager->allocPath(module->path);
            ensure_uc_reg_write(UC_ARM64_REG_X0, &pathAddr);
        });
    }
    if (_dyld_NSGetExecutablePath_address == 0) {
        _dyld_NSGetExecutablePath_address = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            uint64_t bufAddr;
            uint32_t size;
            ensure_uc_reg_read(UC_ARM64_REG_X0, &bufAddr);
            ensure_uc_reg_read(UC_ARM64_REG_W1, &size);
            shared_ptr<MachOModule> module = modules[0];
            string path = module->path;
            assert(size >= path.length() + 1);
            ensure_uc_mem_write(bufAddr, path.c_str(), path.length());
            uint64_t null64 = 0;
            ensure_uc_mem_write(bufAddr + path.length(), &null64, 1);
        });
    }
    if (_dyld_dlsym_address == 0) {
        _dyld_dlsym_address = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            int64_t handle;
            uint64_t symbolAddr;
            ensure_uc_reg_read(UC_ARM64_REG_X0, &handle);
            ensure_uc_reg_read(UC_ARM64_REG_X1, &symbolAddr);
            char *symbolName = MachoMemoryUtils::uc_read_string(uc, symbolAddr, 1000);
            if (handle == IB_RTLD_MAIN_ONLY) {
                if (strcmp(symbolName, "_os_trace_redirect_func") == 0) {
                    assert(false);
                }
            }
            if (strcmp(symbolName, "sandbox_check") == 0) {
                assert(false);
            }
            if (strcmp(symbolName, "_availability_version_check") == 0) {
                assert(false);
            }
            if (strcmp(symbolName, "dispatch_after") == 0) {
                assert(false);
            }
            if (strcmp(symbolName, "dispatch_async") == 0) {
                assert(false);
            }
            
            Symbol *symbol = nullptr;
            string symName = StringUtils::format("_%s", symbolName);
            free(symbolName);
            symbolName = (char *)symName.c_str();
            if (handle > 0) {
                shared_ptr<MachOModule> module = findModuleByAddr(handle);
                symbol = module->getSymbolByName(symbolName, false);
            } else {
                for (shared_ptr<MachOModule> module : modules) {
                    symbol = module->getSymbolByName(symbolName, false);
                    if (symbol) {
                        break;
                    }
                }
            }
            
            uint64_t targetAddr = symbol ? symbol->info->n_value : 0;
            ensure_uc_reg_write(UC_ARM64_REG_X0, &targetAddr);
        });
    }
    
    static uint64_t dyldLazyBinderAddr = 0, dyldFunctionLookupAddr = 0;
    if (dyldLazyBinderAddr == 0) {
        dyldLazyBinderAddr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            assert(false);
        });
    }
    if (dyldFunctionLookupAddr == 0) {
        dyldFunctionLookupAddr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
            uint64_t dyldFuncNameAddr = 0, dyldFuncBindToAddr;
            assert(uc_reg_read(uc, UC_ARM64_REG_X0, &dyldFuncNameAddr) == UC_ERR_OK);
            assert(uc_reg_read(uc, UC_ARM64_REG_X1, &dyldFuncBindToAddr) == UC_ERR_OK);
            char *dyldFuncName = MachoMemoryUtils::uc_read_string(uc, dyldFuncNameAddr, 10000);
            if (strcmp(dyldFuncName, "__dyld_fast_stub_entry") == 0) {
                printf("[+] dyld function lookup - bind %s from 0x%llx to 0x%llx\n", dyldFuncName, _dyld_fast_stub_entryAddr, dyldFuncBindToAddr);
                assert(uc_mem_write(uc, dyldFuncBindToAddr, &_dyld_fast_stub_entryAddr, 8) == UC_ERR_OK);
            } else if (strcmp(dyldFuncName, "__dyld_register_thread_helpers") == 0) {
                printf("[+] dyld function lookup - bind %s from 0x%llx to 0x%llx\n", dyldFuncName, _dyld_register_thread_helpersAddr, dyldFuncBindToAddr);
                assert(uc_mem_write(uc, dyldFuncBindToAddr, &_dyld_register_thread_helpersAddr, 8) == UC_ERR_OK);
            } else if (strcmp(dyldFuncName, "__dyld_get_image_slide") == 0) {
                printf("[+] dyld function lookup - bind %s from 0x%llx to 0x%llx\n", dyldFuncName, _dyld_get_image_slide, dyldFuncBindToAddr);
                assert(uc_mem_write(uc, dyldFuncBindToAddr, &_dyld_get_image_slide, 8) == UC_ERR_OK);
            } else if (strcmp(dyldFuncName, "__dyld_register_func_for_remove_image") == 0) {
                printf("[+] dyld function lookup - bind %s from 0x%llx to 0x%llx\n", dyldFuncName, _dyld_register_func_for_remove_image, dyldFuncBindToAddr);
                assert(uc_mem_write(uc, dyldFuncBindToAddr, &_dyld_register_func_for_remove_image, 8) == UC_ERR_OK);
            } else if (strcmp(dyldFuncName, "__dyld_dyld_register_image_state_change_handler") == 0) {
                // FIXME: objc init
                assert(false);
//                printf("[+] dyld function lookup - bind %s from 0x%llx to 0x%llx\n", dyldFuncName, _dyld_register_image_state_change_handler, dyldFuncBindToAddr);
//                // FIXME: nop objc
//                assert(uc_mem_write(uc, dyldFuncBindToAddr, &_dyld_register_image_state_change_handler, 8) == UC_ERR_OK);
            } else if (strcmp(dyldFuncName, "__dyld_image_path_containing_address") == 0) {
                printf("[+] dyld function lookup - bind %s from 0x%llx to 0x%llx\n", dyldFuncName, _dyld_image_path_containing_address, dyldFuncBindToAddr);
                assert(uc_mem_write(uc, dyldFuncBindToAddr, &_dyld_image_path_containing_address, 8) == UC_ERR_OK);
            } else if (strcmp(dyldFuncName, "__dyld_dlopen") == 0) {
                printf("[+] dyld function lookup - bind %s from 0x%llx to 0x%llx\n", dyldFuncName, _dyld_dlopen_address, dyldFuncBindToAddr);
                assert(uc_mem_write(uc, dyldFuncBindToAddr, &_dyld_dlopen_address, 8) == UC_ERR_OK);
            } else if (strcmp(dyldFuncName, "__dyld_dlsym") == 0) {
                printf("[+] dyld function lookup - bind %s from 0x%llx to 0x%llx\n", dyldFuncName, _dyld_dlsym_address, dyldFuncBindToAddr);
                assert(uc_mem_write(uc, dyldFuncBindToAddr, &_dyld_dlsym_address, 8) == UC_ERR_OK);
            } else if (strcmp(dyldFuncName, "__dyld__NSGetExecutablePath") == 0) {
                printf("[+] dyld function lookup - bind %s from 0x%llx to 0x%llx\n", dyldFuncName, _dyld_NSGetExecutablePath_address, dyldFuncBindToAddr);
                assert(uc_mem_write(uc, dyldFuncBindToAddr, &_dyld_NSGetExecutablePath_address, 8) == UC_ERR_OK);
            } else if (strcmp(dyldFuncName, "__dyld_process_is_restricted") == 0) {
                static uint64_t __dyld_process_is_restricted_address = 0;
                if (__dyld_process_is_restricted_address == 0) {
                    __dyld_process_is_restricted_address = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                            uint64_t null64 = 0;
                            ensure_uc_reg_write(UC_ARM64_REG_X0, &null64);
                        });
                }
                ensure_uc_mem_write(dyldFuncBindToAddr, &__dyld_process_is_restricted_address, 8);
            } else if (strcmp(dyldFuncName, "__dyld_get_all_image_infos") == 0) {
                static uint64_t __dyld_get_all_image_infos_address = 0;
                if (__dyld_get_all_image_infos_address == 0) {
                    static uint64_t infoInVM = 0;
                    if (infoInVM == 0) {
                        size_t size = sizeof(struct dyld_all_image_infos);
                        infoInVM = memoryManager->alloc(size);

                        // init data
                        struct dyld_all_image_infos localInfo = {
                            17, 0, {NULL}, NULL, false, false, (const mach_header*)0x180000000, NULL,
                            "dyld-832.7.3", NULL, 0, NULL, 0, 0, NULL, (struct dyld_all_image_infos *)infoInVM,
                            0, 0, NULL, NULL, NULL, 0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,},
                            0, {0}, "/usr/lib/dyld", {0}, {0}, 0, 0, NULL, 0
                        };
                        localInfo.sharedCacheBaseAddress = 0x180000000;
                        ensure_uc_mem_write(infoInVM, &localInfo, size);
                    }
                    __dyld_get_all_image_infos_address = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                            ensure_uc_reg_write(UC_ARM64_REG_X0, &infoInVM);
                        });
                }
                ensure_uc_mem_write(dyldFuncBindToAddr, &__dyld_get_all_image_infos_address, 8);
            } else if (strcmp(dyldFuncName, "__dyld_register_func_for_add_image") == 0) {
                // dyld FIXME: __dyld_register_func_for_add_image
                static uint64_t _dyld_symbol_addr = 0;
                if (_dyld_symbol_addr == 0) {
                    _dyld_symbol_addr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                        printf("[Stalker][-][Warn] ignore __dyld_register_func_for_add_image !!!\n");
                        uint64_t null64 = 0;
                        ensure_uc_reg_write(UC_ARM64_REG_X0, &null64);
                    });
                }
                ensure_uc_mem_write(dyldFuncBindToAddr, &_dyld_symbol_addr, 8);
            } else if (strcmp(dyldFuncName, "__dyld_objc_notify_register") == 0) {
                // dyld FIXME: __dyld_objc_notify_register
                static uint64_t _dyld_image_map_addr = 0;
                if (_dyld_image_map_addr == 0) {
                    int swi = svcManager->allocateSWI();
                    ks_engine *ks;
                    uint32_t *code = nullptr;
                    size_t codelen = 0;
                    size_t codeCount = 0;
                    string asmText =               "sub sp, sp, #0x10\n"; // 0x7000000c4
                    asmText +=                     "stp x29, x30, [sp]\n";
                    asmText += StringUtils::format("svc #0x%x\n", swi);
                    asmText +=                     "ldr x7, [sp]\n"; // x7 = handler
                    asmText +=                     "add sp, sp, #0x8\n";
                    asmText +=                     "ldr x0, [sp]\n"; // x0 = count
                    asmText +=                     "add sp, sp, #0x8\n";
                    asmText +=                     "ldr x1, [sp]\n"; // x1 = paths
                    asmText +=                     "add sp, sp, #0x8\n";
                    asmText +=                     "ldr x2, [sp]\n"; // x2 = mhs
                    asmText +=                     "add sp, sp, #0x8\n";
                    asmText +=                     "blr x7\n"; // 0x7000000f8 call (*dyld_image_state_change_handler)(enum dyld_image_states state, uint32_t infoCount, const struct dyld_image_info info[])
                    
                    // call to init functions
                    asmText +=                     "ldr x7, [sp]\n"; // x7 = handler
                    asmText +=                     "add sp, sp, #0x8\n";
                    asmText +=                     "cmp x7, #0\n";
                    // Notice: the b #imm is relative from code start **since startaddr is 0**
                    asmText +=                     "b.eq #0x5c\n"; // goto (ldr x0, [sp], pop return value)
                    asmText +=                     "adr lr, #-0xf\n"; // jump to ldr x7, [sp]
                    asmText +=                     "bic lr, lr, #0x1\n"; // clear bit zero

                    asmText +=                     "ldr x0, [sp]\n"; // x0 = path
                    asmText +=                     "add sp, sp, #0x8\n";
                    asmText +=                     "ldr x1, [sp]\n"; // x1 = machHeader
                    asmText +=                     "add sp, sp, #0x10\n"; // skip padding
                    asmText +=                     "br x7\n"; // call (*dyld_image_state_change_handler)(enum dyld_image_states state, uint32_t infoCount, const struct dyld_image_info info[])


                    asmText +=                     "ldr x0, [sp]\n"; // x0 = return value
                    asmText +=                     "add sp, sp, #0x8\n"; // skip padding

                    asmText +=                     "ldp x29, x30, [sp]\n";
                    asmText +=                     "add sp, sp, #0x10\n";
                    asmText +=                     "ret";
                    assert(ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks) == KS_ERR_OK);
                    assert(ks_asm(ks, asmText.c_str(), 0, (unsigned char **)&code, &codelen, &codeCount) == KS_ERR_OK);
                    assert(codelen > 0);
                    _dyld_image_map_addr = svcManager->createSVCWithCustomCode(swi, code, codelen, [&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                        uint64_t mapped, init, unmapped;
                        ensure_uc_reg_read(UC_ARM64_REG_X0, &mapped);
                        ensure_uc_reg_read(UC_ARM64_REG_X1, &init);
                        ensure_uc_reg_read(UC_ARM64_REG_X2, &unmapped);
                        
                        // stack layout
                        // -- init call end --
                        // [return value]
                        // [null]
                        // [pad]
                        // [machHeader]
                        // [path]
                        // [handler]
                        // [pad]
                        // [machHeader]
                        // [path]
                        // [handler]
                        // -- init call begin --
                        // -- mapped call end --
                        // [mhs]
                        // [pahts]
                        // [count]
                        // [handler] <- sp
                        // -- mapped call begin --
                        uint64_t sp;
                        ensure_uc_reg_read(UC_ARM64_REG_SP, &sp);
                        uint64_t returnValue = 0;
                        uint64_t nullSentry = 0;
                        
                        vector<shared_ptr<MachOModule>> objcModules;
                        for (shared_ptr<MachOModule> module : modules) {
                            if (!module->fNotifyObjc) {
                                continue;
                            }
                            objcModules.push_back(module);
                        }
                        
                        // write return value
                        sp -= 8;
                        ensure_uc_mem_write(sp, &returnValue, sizeof(uint64_t));
                        // write sentry
                        sp -= 8;
                        ensure_uc_mem_write(sp, &nullSentry, sizeof(uint64_t));
                        
                        // for init functions
                        for (shared_ptr<MachOModule> module : objcModules) {
                            if (!module->fNotifyObjc) {
                                continue;
                            }
                            uint64_t machHeader = module->machHeader;
                            string path = module->path;
                            uint64_t pathAddr = memoryManager->allocPath(path);
                            assert(pathAddr != 0);
                            
                            // write padding
                            sp -= 8;
                            ensure_uc_mem_write(sp, &nullSentry, sizeof(uint64_t));
                            
                            // write machHeader
                            sp -= 8;
                            ensure_uc_mem_write(sp, &machHeader, sizeof(uint64_t));
                            
                            // write path
                            sp -= 8;
                            ensure_uc_mem_write(sp, &pathAddr, sizeof(uint64_t));
                            
                            // write handler
                            sp -= 8;
                            ensure_uc_mem_write(sp, &init, sizeof(uint64_t));
                        }
                        
                        size_t count = objcModules.size();
                        uint64_t pathsAddr = memoryManager->alloc(sizeof(uint64_t) * count);
                        uint64_t mhsAddr = memoryManager->alloc(sizeof(uint64_t) * count);
                        assert(pathsAddr != 0 && mhsAddr != 0);
                        for (size_t i = 0; i < objcModules.size(); i++) {
                            shared_ptr<MachOModule> module = objcModules[i];
                            uint64_t machHeader = module->machHeader;
                            string path = module->path;
                            uint64_t pathAddr = memoryManager->allocPath(path);
                            assert(pathAddr != 0);
                            ensure_uc_mem_write(pathsAddr + sizeof(uint64_t) * i, &pathAddr, sizeof(uint64_t));
                            ensure_uc_mem_write(mhsAddr + sizeof(uint64_t) * i, &machHeader, sizeof(uint64_t));
                        }
                        
                        // write mhs
                        sp -= 8;
                        ensure_uc_mem_write(sp, &mhsAddr, sizeof(uint64_t));
                        
                        // write paths
                        sp -= 8;
                        ensure_uc_mem_write(sp, &pathsAddr, sizeof(uint64_t));
                        
                        // write count
                        sp -= 8;
                        ensure_uc_mem_write(sp, &count, sizeof(uint64_t));
                        
                        // write handler
                        sp -= 8;
                        ensure_uc_mem_write(sp, &mapped, sizeof(uint64_t));
                        
                        // sync sp
                        ensure_uc_reg_write(UC_ARM64_REG_SP, &sp);
                    });
                }
                ensure_uc_mem_write(dyldFuncBindToAddr, &_dyld_image_map_addr, 8);
            } else if (strcmp(dyldFuncName, "__dyld_get_shared_cache_range") == 0) {
                static uint64_t _dyld_sym_addr = 0;
                if (_dyld_sym_addr == 0) {
                    _dyld_sym_addr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                        uint64_t sizeAddr;
                        ensure_uc_reg_read(UC_ARM64_REG_X0, &sizeAddr);
                        
                        // write size to x0
                        DyldLinkContext &linkContext = this->linkContext;
                        CacheInfo &info = linkContext.loadInfo.info;
                        ib_shared_file_mapping_slide_np *mapping = &info.mappings[info.mappingsCount - 1];
                        uint64_t size = mapping->sms_address + mapping->sms_size - linkContext.loadInfo.slide;
                        ensure_uc_mem_write(sizeAddr, &size, sizeof(uint64_t));
                        
                        // return loadAddress
                        ensure_uc_reg_write(UC_ARM64_REG_X0, &linkContext.loadInfo.loadAddress);
                    });
                }
                ensure_uc_mem_write(dyldFuncBindToAddr, &_dyld_sym_addr, 8);
            } else if (strcmp(dyldFuncName, "__dyld_shared_cache_some_image_overridden") == 0) {
                static uint64_t _dyld_sym_addr = 0;
                if (_dyld_sym_addr == 0) {
                    _dyld_sym_addr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                        syscall_return_value(0);
                    });
                }
                ensure_uc_mem_write(dyldFuncBindToAddr, &_dyld_sym_addr, 8);
            } else if (strcmp(dyldFuncName, "__dyld_is_memory_immutable") == 0) {
                static uint64_t _dyld_sym_addr = 0;
                if (_dyld_sym_addr == 0) {
                    _dyld_sym_addr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                        syscall_return_value(0);
                    });
                }
                ensure_uc_mem_write(dyldFuncBindToAddr, &_dyld_sym_addr, 8);
            } else if (strcmp(dyldFuncName, "__dyld_has_inserted_or_interposing_libraries") == 0) {
                static uint64_t _dyld_sym_addr = 0;
                if (_dyld_sym_addr == 0) {
                    _dyld_sym_addr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                        syscall_return_value(0);
                    });
                }
                ensure_uc_mem_write(dyldFuncBindToAddr, &_dyld_sym_addr, 8);
            } else if (strcmp(dyldFuncName, "__dyld_register_for_bulk_image_loads") == 0) {
                // dyld FIXME: ignore __dyld_register_for_bulk_image_loads
                static uint64_t _dyld_sym_addr = 0;
                if (_dyld_sym_addr == 0) {
                    _dyld_sym_addr = svcManager->createSVC([&](uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
                        printf("[Stalker][-][Warn] ignore __dyld_register_for_bulk_image_loads\n");
                        syscall_return_value(0);
                    });
                }
                ensure_uc_mem_write(dyldFuncBindToAddr, &_dyld_sym_addr, 8);
            } else {
                uc_debug_print_backtrace(uc);
                assert(false);
            }
            free(dyldFuncName);
        });
    }
    
    // FATAL FIXME: hardcode _dyld_function_lookup addr
    uint64_t _dyld_function_lookup_addr = 0x1D2896F78;
    assert(uc_mem_write(uc, _dyld_function_lookup_addr, &dyldFunctionLookupAddr, 8) == UC_ERR_OK);
    return mainModule;
}

shared_ptr<MachOModule> MachOLoader::_loadModuleFromFile(DyldLinkContext linkContext, std::string filePath, bool loadDylibs) {
    string moduleName = StringUtils::path_basename(filePath);
    if (name2module.find(moduleName) != name2module.end()) {
        return name2module[moduleName];
    }
    
    char *shadowFilePath = nullptr;
    if (workDirManager->createShadowFile(filePath, &shadowFilePath) != 0) {
        assert(false);
        return NULL;
    }
    
    if (shadowFilePath == nullptr) {
        assert(false);
        return NULL;
    }
    
    string orignalPath = filePath;
    filePath = shadowFilePath;
    
    shared_ptr<MachOModule> module = make_shared<MachOModule>();
    module->name = moduleName;
    module->path = filePath;
    module->orignalPath = orignalPath;
    uint8_t *mappedFile;
    uint64_t bufferSize;
    ib_mach_header_64 *hdr = nullptr;
    scanner_err serr = ScannerContext::headerDetector(filePath, &mappedFile, &bufferSize, &hdr);
    if (serr != SC_ERR_OK) {
        assert(false);
        return NULL;
    }
    
    // parse section headers
    // vmaddr base
    uint64_t imageBase = loaderOffset;
    uint64_t imageSize = 0;
    vector<pair<uint64_t, uint64_t>> textSects;
    uint64_t vmaddr_bss_start = 0;
    uint64_t vmaddr_bss_end = 0;
    uint64_t got_start = 0, got_size = 0;
    uint64_t common_start = 0, common_size = 0;
    
    // offset, size, baseAddr, sect
    vector<pair<pair<uint64_t, uint64_t>, pair<uint64_t, ib_section_64 *>>> allRelocs;
    
    struct ib_symtab_command *symtab_cmd = nullptr;
    struct ib_dysymtab_command *dysymtab_cmd = nullptr;
    struct ib_segment_command_64 *textSeg64 = nullptr;
    struct ib_section_64 *textSect = nullptr;
    struct ib_entry_point_command *mainSeg = nullptr;
    struct ib_dyld_info_command *dyld_info = nullptr;
    uint64_t objc_classlist_addr = 0, objc_catlist_addr = 0;
    uint64_t objc_classlist_size = 0, objc_catlist_size = 0;
    std::vector<struct ib_section_64 *> sectionHeaders;
    std::vector<struct ib_segment_command_64 *> segmentHeaders;
    
    // symtab、dlsymtab、strtab's vmaddr base on LINKEDIT's vmaddr
    uint64_t linkedit_base = 0;
    uint64_t symoff = 0, symsize = 0;
    uint64_t stroff = 0, strsize = 0;
    uint32_t ncmds = hdr->ncmds;
    uint8_t *cmds = mappedFile + sizeof(struct ib_mach_header_64);
    
    vector<MachODynamicLibrary> dynamicLibraryDependencies;
    vector<MachODynamicLibrary> dynamicLibraryOrdinalList;
    vector<MachODynamicLibrary> exportDynamicLibraries;
    vector<MachODynamicLibrary> dynamicLibraryDependenciesUnupward;
    vector<MachOModInitFunc> modInitFuncList;
    vector<MachORoutine> routineList;
    printf("[+] MachOLoader - load module %s (%s) with offset 0x%llx\n", moduleName.c_str(), filePath.c_str(), imageBase);
    uint64_t machHeader = 0;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct ib_load_command *lc = (struct ib_load_command *)cmds;
        switch (lc->cmd) {
            case IB_LC_SEGMENT_64: {
                struct ib_segment_command_64 *seg64 = (struct ib_segment_command_64 *)lc;
                segmentHeaders.push_back(seg64);
                
                uint64_t addr = seg64->vmaddr + imageBase;
                // update header
                seg64->vmaddr = addr;
                
                uint64_t size = std::min(seg64->vmsize, seg64->filesize);
                if (size == 0) {
                    cmds += lc->cmdsize;
                    continue;
                }
                uc_err err = uc_mem_write(uc, addr, mappedFile + seg64->fileoff, size);
                if (err != UC_ERR_OK) {
                    cout << termcolor::red << "[-] VirtualMemoryV2 - Error: cannot map segment ";
                    cout << termcolor::red << StringUtils::format("%s(0x%llx~0x%llx)",
                                                                  seg64->segname,
                                                                  seg64->vmaddr,
                                                                  seg64->vmaddr + size);
                    cout << ", error " << uc_strerror(err);
                    cout << termcolor::reset << endl;
                    assert(false);
                    return NULL;
                }
                printf("[+]   mapping %s: 0x%llx - 0x%llx\n", seg64->segname, addr, addr + size);
                
                if (strncmp(seg64->segname, "__TEXT", 6) == 0) {
                    textSeg64 = seg64;
                    if (!machHeader) {
                        machHeader = seg64->vmaddr;
                    }
                } else if (strncmp(seg64->segname, "__LINKEDIT", 10) == 0) {
                    linkedit_base = seg64->vmaddr - seg64->fileoff;
                }
                
                if (seg64->nsects > 0) {
                    struct ib_section_64 *sect = (struct ib_section_64 *)((uint8_t *)seg64 + sizeof(struct ib_segment_command_64));
                    for (uint32_t i = 0; i < seg64->nsects; i++) {
                        // update sect addr
                        sect->addr += imageBase;
                        
                        char *sectname = (char *)malloc(17);
                        memcpy(sectname, sect->sectname, 16);
                        sectname[16] = 0;
                        module->addr2segInfo[sect->addr] = {string(sect->segname), string(sectname)};
                        if (strcmp(sectname, "__text") == 0) {
                            textSects.push_back({sect->addr, sect->size});
                            textSect = sect;
                        }
                        if (strcmp(sectname, "__bss") == 0) {
                            vmaddr_bss_start = sect->addr;
                            vmaddr_bss_end = vmaddr_bss_start + sect->size;
                        }
                        if (strcmp(sectname, "__objc_imageinfo") == 0) {
                            module->fNotifyObjc = true;
                        }
                        if (strcmp(sectname, "__objc_classlist") == 0) {
                            objc_classlist_addr = sect->addr;
                            objc_classlist_size = sect->size;
                        }
                        if (strcmp(sectname, "__objc_catlist") == 0) {
                            objc_catlist_addr = sect->addr;
                            objc_catlist_size = sect->size;
                        }
                        if (strcmp(sectname, "__got") == 0) {
                            got_start = sect->addr;
                            got_size = sect->size;
                        }
                        if (strcmp(sectname, "__common") == 0) {
                            common_start = sect->addr;
                            common_size = sect->size;
                        }
                        if (sect->reloff > 0 && sect->nreloc > 0) {
                            allRelocs.push_back({{sect->reloff, sect->nreloc}, {sect->addr, sect}});
                        }
                        
                        uint64_t addr = sect->addr;
                        uc_err err = uc_mem_write(uc, addr, mappedFile + sect->offset, sect->size);
                        if (err != UC_ERR_OK) {
                            cout << termcolor::red << "[-] VirtualMemoryV2 - Error: cannot map section ";
                            cout << StringUtils::format("%s(0x%llx~0x%llx)",
                                                        sect->segname,
                                                        sect->addr,
                                                        addr + sect->size);
                            cout << ", error " << uc_strerror(err);
                            cout << termcolor::reset << endl;
                            assert(false);
                        }
                        printf("[+]     mapping %s.%s: 0x%llx - 0x%llx\n", sect->segname, sectname, addr, addr + size);
                        sectionHeaders.push_back(sect);
                        
                        // check mod_init_func
                        uint32_t type = sect->flags & IB_SECTION_TYPE;
                        if (type == IB_S_MOD_INIT_FUNC_POINTERS) {
                            uint64_t count = sect->size / sizeof(uint64_t);
                            uint64_t *modInitFuncs = (uint64_t *)(mappedFile + sect->offset);
                            for (uint64_t i = 0; i < count; i++) {
                                uint64_t funcAddr = *modInitFuncs + imageBase;
                                modInitFuncList.push_back({ .addr = funcAddr });
                                modInitFuncs += 1;
                            }
                        }
                        
                        free(sectname);
                        sect += 1;
                    }
                }
                
                // update size
                uint64_t totalSize = seg64->vmaddr + seg64->vmsize - imageBase;
                if (imageSize < totalSize) {
                    imageSize = totalSize;
                }
                break;
            }
            case IB_LC_ROUTINES_64: {
                struct ib_routines_command_64 *routine_cmd = (struct ib_routines_command_64 *)lc;
                uint64_t addr = routine_cmd->init_address + imageBase;
                routineList.push_back({ .addr = addr });
                break;
            }
            case IB_LC_SYMTAB: {
                symtab_cmd = (struct ib_symtab_command *)lc;
                symoff = symtab_cmd->symoff;
                symsize = symtab_cmd->nsyms * sizeof(ib_nlist_64);
                stroff = symtab_cmd->stroff;
                strsize = symtab_cmd->strsize;
                break;
            }
            case IB_LC_DYSYMTAB: {
                dysymtab_cmd = (struct ib_dysymtab_command *)lc;
                break;
            }
            case IB_LC_DYLD_INFO_ONLY: {
                dyld_info = (struct ib_dyld_info_command *)lc;
                break;
            }
            case IB_LC_MAIN: {
                struct ib_entry_point_command *lc_main = (struct ib_entry_point_command *)lc;
                mainSeg = lc_main;
                break;
            }
            case IB_LC_LOAD_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)lc;
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryDependencies.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                break;
            }
            case IB_LC_LOAD_WEAK_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)lc;
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryDependencies.push_back({.name = name, .path = std::string(path), .upward = false, .weak = true});
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = false, .weak = true});
                break;
            }
            case IB_LC_REEXPORT_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)lc;
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                exportDynamicLibraries.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                break;
            }
            case IB_LC_LAZY_LOAD_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)lc;
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                break;
            }
            case IB_LC_LOAD_UPWARD_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)lc;
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryDependencies.push_back({.name = name, .path = std::string(path), .upward = true, .weak = false});
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = true, .weak = false});
                break;
            }
            default:
                break;
        }
        cmds += lc->cmdsize;
    }
    
    // sync machHeader
    uint32_t lcsize = hdr->sizeofcmds;
    uint64_t hdrAddr = imageBase > 0 ? imageBase : 0x100000000 ;
    assert(uc_mem_write(uc, hdrAddr, mappedFile, lcsize) == UC_ERR_OK);
    
    // init bss
    uint64_t bssSize = vmaddr_bss_end - vmaddr_bss_start;
    if (bssSize > 0) {
        void *bssData = calloc(1, bssSize);
        assert(uc_mem_write(uc, vmaddr_bss_start, bssData, bssSize) == UC_ERR_OK);
        free(bssData);
    }
    
    // init common
    if (common_start > 0 && common_size > 0) {
        void *data = calloc(1, common_size);
        assert(uc_mem_write(uc, common_start, data, common_size) == UC_ERR_OK);
        free(data);
    }
    
    loaderOffset += imageSize;
    module->machHeader = machHeader;
    module->modInitFuncs = modInitFuncList;
    module->routines = routineList;
    
    shared_ptr<StringTable> strtab = make_shared<StringTable>();
    module->strtab = strtab;
    uint64_t strtab_vmaddr = linkedit_base + symtab_cmd->stroff;
    strtab->buildStringTable(strtab_vmaddr, mappedFile + symtab_cmd->stroff, symtab_cmd->strsize);
    
    // sort sectionHeaders by offset
    sort(sectionHeaders.begin(), sectionHeaders.end(), [&](struct ib_section_64 *a, struct ib_section_64 *b) {
        return a->offset < b->offset;
    });
    
    shared_ptr<SymbolTable> symtab = make_shared<SymbolTable>(strtab);
    symtab->moduleBase = imageBase;
    if (dyld_info) {
        symtab->buildExportNodes(mappedFile, dyld_info->export_off, dyld_info->export_size);
    }
    module->symtab = symtab;
    symtab->buildSymbolTable(moduleName, mappedFile + symtab_cmd->symoff, symtab_cmd->nsyms);
    if (dysymtab_cmd) {
        symtab->buildDynamicSymbolTable(sectionHeaders, mappedFile + dysymtab_cmd->indirectsymoff, dysymtab_cmd->nindirectsyms, mappedFile);
    }
    symtab->sync();
    
    // map symtab & strtab
    uc_err err = uc_mem_write(uc, linkedit_base + symoff, mappedFile + symoff, symsize);
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] VirtualMemoryV2 - Error: cannot map symbol table: " << uc_strerror(err);
        cout << termcolor::reset << endl;
        assert(false);
        return NULL;
    }
    
    err = uc_mem_write(uc, linkedit_base + stroff, mappedFile + stroff, strsize);
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] VirtualMemoryV2 - Error: cannot map string table: " << uc_strerror(err);
        cout << termcolor::reset << endl;
        assert(false);
        return NULL;
    }
    
//    if (uc != this->uc) {
//        // sync text segment since we may have fixed it
//        for (pair<uint64_t, uint32_t> patch : textPatch) {
//            uc_mem_write(uc, patch.first, &patch.second, sizeof(uint32_t));
//        }
//        relocAllRegions(symtab, objcRuntime, uc);
//    }
    
    // handle export dylibs
    for (MachODynamicLibrary &library : exportDynamicLibraries) {
        string path = resolveLibraryPath(library.path);
        if (path.length() > 0) {
            _loadModuleFromFileUsingSharedCache(linkContext, path, false);
        } else {
            cout << termcolor::yellow << StringUtils::format("[-] MachOLoader - Error: unable to export dependent dylib %s", library.name.c_str());
            cout << termcolor::reset << endl;
        }
    }
    
    module->addr = imageBase;
    module->size = imageSize;
    module->linkedit_base = linkedit_base;
    module->dynamicLibraryDependencies = dynamicLibraryDependencies;
    module->dynamicLibraryOrdinalList = dynamicLibraryOrdinalList;
    module->exportDynamicLibraries = exportDynamicLibraries;
    module->dyldInfoCommand = dyld_info;
    module->mappedBuffer = mappedFile;
    module->segmentHeaders = segmentHeaders;
    module->sectionHeaders = sectionHeaders;
    module->loader = shared_from_this();
    
    modules.push_back(module);
    assert(name2module.find(moduleName) == name2module.end());
    name2module[moduleName] = module;
    addr2module[module->addr] = module;
    
    // rebase module
    if (imageBase > 0) {
        DyldSimulator::doRebase(imageBase, imageSize, mappedFile, segmentHeaders, dyld_info, [&](uint64_t addr, uint64_t slide, uint8_t type) {
            switch (type) {
                case IB_REBASE_TYPE_POINTER:
                case IB_REBASE_TYPE_TEXT_ABSOLUTE32: {
                    uint64_t ptrAddr = addr;
                    uint64_t ptrValue = 0;
                    uc_err err = uc_mem_read(uc, ptrAddr, &ptrValue, 8);
                    if (err != UC_ERR_OK) {
                        cout << termcolor::red << StringUtils::format("[-] MachOLoader - Error: cannot do rebase at 0x%llx, %s", addr, uc_strerror(err));
                        cout << termcolor::reset << endl;
                        assert(false);
                    }
                    
                    ptrValue += imageBase;
                    err = uc_mem_write(uc, ptrAddr, &ptrValue, 8);
                    if (err != UC_ERR_OK) {
                        cout << termcolor::red << StringUtils::format("[-] MachOLoader - Error: cannot do rebase at 0x%llx, %s", addr, uc_strerror(err));
                        cout << termcolor::reset << endl;
                        assert(false);
                    }
                    break;
                }
                default:
                    assert(false);
                    break;
            }
        });
    }
    
    // load dependencies
    if (loadDylibs) {
        for (MachODynamicLibrary &library : dynamicLibraryDependencies) {
            if (library.name == "UIKit") {
                printf("[-] Warn: ignore UIKit\n");
                continue;
            }
            string path = resolveLibraryPath(library.path);
            if (path.length() != 0) {
                _loadModuleFromFileUsingSharedCache(linkContext, path, true);
            } else {
                cout << termcolor::yellow << StringUtils::format("[-] MachOLoader - Error: unable to load dependent dylib %s", library.path.c_str());
                cout << termcolor::reset << endl;
            }
            if (!library.upward) {
                dynamicLibraryDependenciesUnupward.push_back(library);
            }
        }
    }
    
    module->dynamicLibraryDependenciesUnupward = dynamicLibraryDependenciesUnupward;
    return module;
}

shared_ptr<MachOModule> MachOLoader::_loadModuleFromFileUsingSharedCache(DyldLinkContext linkContext, std::string filePath, bool loadDylibs) {
    string moduleName = StringUtils::path_basename(filePath);
    if (name2module.find(moduleName) != name2module.end()) {
        return name2module[moduleName];
    }
    
//    char *shadowFilePath = nullptr;
//    if (workDirManager->createShadowFile(filePath, &shadowFilePath) != 0) {
//        assert(false);
//        return NULL;
//    }
//
//    if (shadowFilePath == nullptr) {
//        assert(false);
//        return NULL;
//    }
    SharedCacheFindDylibResults findResult;
    bool findInCache = findInSharedCacheImage(linkContext.uc, linkContext.loadInfo, filePath.c_str(), &findResult);
    assert(findInCache);
    
    shared_ptr<MachOModule> module = make_shared<MachOModule>();
    module->name = moduleName;
    module->path = filePath;
    module->orignalPath = findResult.pathInCache;

    ib_mach_header_64 hdr = {0};
    assert(uc_mem_read(uc, findResult.mhInCache, &hdr, sizeof(ib_mach_header_64)) == UC_ERR_OK);
    
    // parse section headers
    // vmaddr base
    uint64_t imageBase = findResult.mhInCache;
    uint64_t imageSize = 0;
    vector<pair<uint64_t, uint64_t>> textSects;
    uint64_t vmaddr_bss_start = 0;
    uint64_t vmaddr_bss_end = 0;
    uint64_t got_start = 0, got_size = 0;
    uint64_t common_start = 0, common_size = 0;
    
    // offset, size, baseAddr, sect
    vector<pair<pair<uint64_t, uint64_t>, pair<uint64_t, ib_section_64 *>>> allRelocs;
    
    struct ib_symtab_command *symtab_cmd = nullptr;
    struct ib_dysymtab_command *dysymtab_cmd = nullptr;
    struct ib_segment_command_64 *textSeg64 = nullptr;
    struct ib_section_64 *textSect = nullptr;
    struct ib_dyld_info_command *dyld_info = nullptr;
    uint64_t objc_classlist_addr = 0, objc_catlist_addr = 0;
    uint64_t objc_classlist_size = 0, objc_catlist_size = 0;
    std::vector<struct ib_section_64 *> sectionHeaders;
    std::vector<struct ib_segment_command_64 *> segmentHeaders;
    
    // symtab、dlsymtab、strtab's vmaddr base on LINKEDIT's vmaddr
    uint64_t linkedit_base = 0;
    uint64_t symoff = 0, symsize = 0;
    uint64_t stroff = 0, strsize = 0;
    uint32_t ncmds = hdr.ncmds;
    uint64_t cmdsAddr = findResult.mhInCache + sizeof(struct ib_mach_header_64);
    
    vector<MachODynamicLibrary> dynamicLibraryDependencies;
    vector<MachODynamicLibrary> dynamicLibraryOrdinalList;
    vector<MachODynamicLibrary> exportDynamicLibraries;
    vector<MachODynamicLibrary> dynamicLibraryDependenciesUnupward;
    vector<MachOModInitFunc> modInitFuncList;
    vector<MachORoutine> routineList;
    printf("[+] MachOLoader - load module %s (%s) with offset 0x%llx\n", moduleName.c_str(), filePath.c_str(), imageBase);
    uint64_t machHeader = 0;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct ib_load_command lc;
        ensure_uc_mem_read(cmdsAddr, &lc, sizeof(ib_load_command));
        switch (lc.cmd) {
            case IB_LC_SEGMENT_64: {
                struct ib_segment_command_64 *seg64 = (struct ib_segment_command_64 *)malloc(sizeof(struct ib_segment_command_64));
                ensure_uc_mem_read(cmdsAddr, seg64, sizeof(struct ib_segment_command_64));
                segmentHeaders.push_back(seg64);
                
                uint64_t size = std::min(seg64->vmsize, seg64->filesize);
                if (size == 0) {
                    cmdsAddr += lc.cmdsize;
                    continue;
                }
                
                if (strncmp(seg64->segname, "__TEXT", 6) == 0) {
                    textSeg64 = seg64;
                    if (!machHeader) {
                        machHeader = seg64->vmaddr;
                    }
                } else if (strncmp(seg64->segname, "__LINKEDIT", 10) == 0) {
                    linkedit_base = seg64->vmaddr - seg64->fileoff;
                }
                
                if (seg64->nsects > 0) {
                    uint64_t sectAddr = cmdsAddr + sizeof(struct ib_segment_command_64);
                    for (uint32_t i = 0; i < seg64->nsects; i++) {
                        struct ib_section_64 *sect = (struct ib_section_64 *)malloc(sizeof(struct ib_section_64));
                        ensure_uc_mem_read(sectAddr, sect, sizeof(struct ib_section_64));
                        
                        char *sectname = (char *)malloc(17);
                        memcpy(sectname, sect->sectname, 16);
                        sectname[16] = 0;
                        module->addr2segInfo[sect->addr] = {string(sect->segname), string(sectname)};
                        if (strcmp(sectname, "__text") == 0) {
                            textSects.push_back({sect->addr, sect->size});
                            textSect = sect;
                        }
                        if (strcmp(sectname, "__bss") == 0) {
                            vmaddr_bss_start = sect->addr;
                            vmaddr_bss_end = vmaddr_bss_start + sect->size;
                        }
                        if (strcmp(sectname, "__objc_imageinfo") == 0) {
                            module->fNotifyObjc = true;
                        }
                        if (strcmp(sectname, "__objc_classlist") == 0) {
                            objc_classlist_addr = sect->addr;
                            objc_classlist_size = sect->size;
                        }
                        if (strcmp(sectname, "__objc_catlist") == 0) {
                            objc_catlist_addr = sect->addr;
                            objc_catlist_size = sect->size;
                        }
                        if (strcmp(sectname, "__got") == 0) {
                            got_start = sect->addr;
                            got_size = sect->size;
                        }
                        if (strcmp(sectname, "__common") == 0) {
                            common_start = sect->addr;
                            common_size = sect->size;
                        }
                        if (sect->reloff > 0 && sect->nreloc > 0) {
                            allRelocs.push_back({{sect->reloff, sect->nreloc}, {sect->addr, sect}});
                        }
                        
                        sectionHeaders.push_back(sect);
                        
                        // check mod_init_func
                        uint32_t type = sect->flags & IB_SECTION_TYPE;
                        if (type == IB_S_MOD_INIT_FUNC_POINTERS) {
                            uint64_t count = sect->size / sizeof(uint64_t);
                            uint64_t size = sizeof(uint64_t) * count;
                            uint64_t *modInitFuncs = (uint64_t *)malloc(size);
                            uint64_t *modInitFuncsHead = modInitFuncs;
                            ensure_uc_mem_read(sect->addr, modInitFuncs, size);
                            for (uint64_t i = 0; i < count; i++) {
                                uint64_t funcAddr = *modInitFuncs & 0xfffffffffULL;
                                modInitFuncList.push_back({ .addr = funcAddr });
                                modInitFuncs += 1;
                            }
                            free(modInitFuncsHead);
                        }
                        
                        free(sectname);
                        sectAddr += sizeof(struct ib_section_64);
                    }
                }
                
                // update size
                uint64_t totalSize = seg64->vmaddr + seg64->vmsize - imageBase;
                if (imageSize < totalSize) {
                    imageSize = totalSize;
                }
                break;
            }
            case IB_LC_ROUTINES_64: {
                struct ib_routines_command_64 routine_cmd;
                ensure_uc_mem_read(cmdsAddr, &routine_cmd, sizeof(ib_routines_command_64));
                uint64_t addr = routine_cmd.init_address + imageBase;
                routineList.push_back({ .addr = addr });
                break;
            }
            case IB_LC_SYMTAB: {
                symtab_cmd = (struct ib_symtab_command *)malloc(sizeof(ib_symtab_command));
                ensure_uc_mem_read(cmdsAddr, symtab_cmd, sizeof(ib_symtab_command));
                symoff = symtab_cmd->symoff;
                symsize = symtab_cmd->nsyms * sizeof(ib_nlist_64);
                stroff = symtab_cmd->stroff;
                strsize = symtab_cmd->strsize;
                break;
            }
            case IB_LC_DYSYMTAB: {
                dysymtab_cmd = (struct ib_dysymtab_command *)malloc(sizeof(struct ib_dysymtab_command));
                ensure_uc_mem_read(cmdsAddr, dysymtab_cmd, sizeof(struct ib_dysymtab_command));
                break;
            }
            case IB_LC_DYLD_INFO_ONLY: {
                dyld_info = (struct ib_dyld_info_command *)malloc(sizeof(ib_dyld_info_command));
                ensure_uc_mem_read(cmdsAddr, dyld_info, sizeof(ib_dyld_info_command));
                break;
            }
            case IB_LC_MAIN: {
                assert(false);
                break;
            }
            case IB_LC_LOAD_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)malloc(lc.cmdsize);
                ensure_uc_mem_read(cmdsAddr, dylib_cmd, lc.cmdsize);
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryDependencies.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                free(dylib_cmd);
                break;
            }
            case IB_LC_LOAD_WEAK_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)malloc(lc.cmdsize);
                ensure_uc_mem_read(cmdsAddr, dylib_cmd, lc.cmdsize);
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryDependencies.push_back({.name = name, .path = std::string(path), .upward = false, .weak = true});
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = false, .weak = true});
                free(dylib_cmd);
                break;
            }
            case IB_LC_REEXPORT_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)malloc(lc.cmdsize);
                ensure_uc_mem_read(cmdsAddr, dylib_cmd, lc.cmdsize);
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                exportDynamicLibraries.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                free(dylib_cmd);
                break;
            }
            case IB_LC_LAZY_LOAD_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)malloc(lc.cmdsize);
                ensure_uc_mem_read(cmdsAddr, dylib_cmd, lc.cmdsize);
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = false, .weak = false});
                free(dylib_cmd);
                break;
            }
            case IB_LC_LOAD_UPWARD_DYLIB: {
                struct ib_dylib_command *dylib_cmd = (struct ib_dylib_command *)malloc(lc.cmdsize);
                ensure_uc_mem_read(cmdsAddr, dylib_cmd, lc.cmdsize);
                const char *path = (const char *)dylib_cmd + dylib_cmd->dylib.name.offset;
                string name = StringUtils::path_basename(std::string(path));
                dynamicLibraryDependencies.push_back({.name = name, .path = std::string(path), .upward = true, .weak = false});
                dynamicLibraryOrdinalList.push_back({.name = name, .path = std::string(path), .upward = true, .weak = false});
                free(dylib_cmd);
                break;
            }
            default:
                break;
        }
        cmdsAddr += lc.cmdsize;
    }
    
    // init bss
    uint64_t bssSize = vmaddr_bss_end - vmaddr_bss_start;
    if (bssSize > 0) {
        void *bssData = calloc(1, bssSize);
        assert(uc_mem_write(uc, vmaddr_bss_start, bssData, bssSize) == UC_ERR_OK);
        free(bssData);
    }
    
    // init common
    if (common_start > 0 && common_size > 0) {
        void *data = calloc(1, common_size);
        assert(uc_mem_write(uc, common_start, data, common_size) == UC_ERR_OK);
        free(data);
    }
    
    loaderOffset += imageSize;
    module->machHeader = machHeader;
    module->modInitFuncs = modInitFuncList;
    module->routines = routineList;
    
    uint64_t strtab_vmaddr = linkedit_base + symtab_cmd->stroff;
    shared_ptr<StringTable> strtab = StringTable::makeOrGetSharedStringTable(linkContext, strtab_vmaddr, symtab_cmd->strsize);
    module->strtab = strtab;
    
    // sort sectionHeaders by offset
    sort(sectionHeaders.begin(), sectionHeaders.end(), [&](struct ib_section_64 *a, struct ib_section_64 *b) {
        return a->offset < b->offset;
    });
    
    shared_ptr<SymbolTable> symtab = make_shared<SymbolTable>(strtab);
    symtab->moduleBase = imageBase;
    if (dyld_info) {
        symtab->buildExportNodes(linkContext, linkedit_base, dyld_info->export_off, dyld_info->export_size);
    }
    module->symtab = symtab;
    
    size_t symtab_size = sizeof(ib_nlist_64) * symtab_cmd->nsyms;
    uint8_t *symtab_data = (uint8_t *)malloc(symtab_size);
    uint64_t symtab_addr = linkedit_base + symtab_cmd->symoff;
    ensure_uc_mem_read(symtab_addr, symtab_data, symtab_size);
    symtab->buildSymbolTable(moduleName, symtab_data, symtab_cmd->nsyms);
    if (dysymtab_cmd) {
        size_t dysymtab_size = sizeof(uint32_t) * dysymtab_cmd->nindirectsyms;
        uint8_t *dysymtab_data = (uint8_t *)malloc(dysymtab_size);
        uint64_t dysymtab_addr = linkedit_base + dysymtab_cmd->indirectsymoff;
        ensure_uc_mem_read(dysymtab_addr, dysymtab_data, dysymtab_size);
        symtab->buildDynamicSymbolTable(linkContext, sectionHeaders, dysymtab_data, dysymtab_cmd->nindirectsyms);
    }
    symtab->sync();
    
    // map symtab & strtab
    
//    if (uc != this->uc) {
//        // sync text segment since we may have fixed it
//        for (pair<uint64_t, uint32_t> patch : textPatch) {
//            uc_mem_write(uc, patch.first, &patch.second, sizeof(uint32_t));
//        }
//        relocAllRegions(symtab, objcRuntime, uc);
//    }
    
    // handle export dylibs
    for (MachODynamicLibrary &library : exportDynamicLibraries) {
        string path = resolveLibraryPath(library.path);
        if (path.length() > 0) {
            _loadModuleFromFileUsingSharedCache(linkContext, path, false);
        } else {
            cout << termcolor::yellow << StringUtils::format("[-] MachOLoader - Error: unable to export dependent dylib %s", library.name.c_str());
            cout << termcolor::reset << endl;
        }
    }
    
    module->addr = imageBase;
    module->size = imageSize;
    module->linkedit_base = linkedit_base;
    module->dynamicLibraryDependencies = dynamicLibraryDependencies;
    module->dynamicLibraryOrdinalList = dynamicLibraryOrdinalList;
    module->exportDynamicLibraries = exportDynamicLibraries;
    module->dyldInfoCommand = dyld_info;
    module->segmentHeaders = segmentHeaders;
    module->sectionHeaders = sectionHeaders;
    module->loader = shared_from_this();
    
    modules.push_back(module);
    assert(name2module.find(moduleName) == name2module.end());
    name2module[moduleName] = module;
    addr2module[module->addr] = module;
    
    // rebase module
    if (imageBase > 0) {
        // FIXME: rebase info uc
        assert(dyld_info->rebase_size == 0);
    }
    
    // load dependencies
    if (loadDylibs) {
        for (MachODynamicLibrary &library : dynamicLibraryDependencies) {
            string path = resolveLibraryPath(library.path);
            if (path.length() != 0) {
                _loadModuleFromFileUsingSharedCache(linkContext, path, true);
            } else {
                cout << termcolor::yellow << StringUtils::format("[-] MachOLoader - Error: unable to load dependent dylib %s", library.path.c_str());
                cout << termcolor::reset << endl;
            }
            if (!library.upward) {
                dynamicLibraryDependenciesUnupward.push_back(library);
            }
        }
    }
    
    module->dynamicLibraryDependenciesUnupward = dynamicLibraryDependenciesUnupward;
    return module;
}

shared_ptr<MachOModule> MachOLoader::findModuleByName(string moduleName) {
//    if (moduleName.rfind("libc++") != string::npos) {
//        StringUtils::replace(moduleName, "libc++", "libcpp");
//    }
    if (name2module.find(moduleName) == name2module.end()) {
        if (moduleName != "libsystem_stats.dylib") {
//            assert(false);
        }
        return nullptr;
    }
    return name2module[moduleName];
}

shared_ptr<MachOModule> MachOLoader::findModuleByAddr(uint64_t addr) {
    auto moduleIt = addr2module.lower_bound(addr);
    if (moduleIt == addr2module.end()) {
        return nullptr;
    }

    shared_ptr<MachOModule> module = moduleIt->second;
    if (addr >= module->addr && addr < (module->addr + module->size)) {
        return module;
    }
    assert(moduleIt != addr2module.begin());
    module = (--moduleIt)->second;
    if (addr >= module->addr && addr < (module->addr + module->size)) {
        return module;
    }
    
    assert(false);
    return nullptr;
}

Symbol * MachOLoader::getSymbolByAddress(uint64_t addr) {
    for (shared_ptr<MachOModule> module : modules) {
        Symbol *sym = module->getSymbolByAddress(addr);
        if (sym) {
            return sym;
        }
    }
    return nullptr;
}

void MachOLoader::printImageList(void) {
    printf("[Stalker][Dyld] =====================> ImageList - Begin\n");
    int i = 0;
    sort(modules.begin(), modules.end(), [](shared_ptr<MachOModule> m1, shared_ptr<MachOModule> m2) {
        return m1->addr < m2->addr;
    });
    for (shared_ptr<MachOModule> module : modules) {
        uint64_t addr = module->addr;
        if (addr == 0x0) {
            addr = 0x100000000;
        }
        string line = StringUtils::format("[Stalker][Dyld][%3d] 0x%llx %s: [", i, addr, module->path.c_str());
        for (MachODynamicLibrary &library : module->dynamicLibraryDependencies) {
            line += library.name;
            if (library.weak || library.upward) {
                line += '(';
                if (library.weak) {
                    line += 'w';
                }
                if (library.upward) {
                    line += 'u';
                }
                line += ')';
            }
            line += ", ";
        }
        line += "]\n";
        printf("%s", line.c_str());
        i++;
    }
    printf("[Stalker][Dyld] <===================== ImageList - Begin\n");
}
