//
//  SymbolWrapperScanner.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "SymbolWrapperScanner.hpp"
#include "ARM64Disasembler.hpp"
#include "ARM64Runtime.hpp"
#include "VirtualMemoryV2.hpp"
#include "SymbolTable.hpp"
#include "termcolor.h"
#include "StringUtils.h"
#include "SymbolWrapperSerializationManager.hpp"
#include <set>
#include <pthread.h>

using namespace std;
using namespace iblessing;
static uc_hook memexp_hook;

static bool mem_exception_hook_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
//    printf("[----------------] error !!!\n");
//    printf("\n****** mem read failed %d 0x%llx, %d*******\n", type, address, size);
    return false;
}

void SymbolWrapperScanner::init() {
    pthread_mutexattr_t attr = {0};
    assert(pthread_mutexattr_init(&attr) == 0);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    assert(pthread_mutex_init(&wrapperLock, &attr) == 0);
    
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("\t[-] error: %s\n", uc_strerror(err));
        assert(false);
    }
    uc_hook_add(uc, &memexp_hook, UC_HOOK_MEM_INVALID, (void *)mem_exception_hook_callback, NULL, 1, 0);
    
    // setup default thread state
    assert(uc_context_alloc(uc, &ctx) == UC_ERR_OK);
    
    uint64_t unicorn_sp_start = 0x200000000;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    uc_context_save(uc, ctx);
    
    // setup common protos
    symbol2proto["_objc_msgSend"] = {2, true, "id", {"id", "const char*", "..."}};
    symbol2proto["_objc_retain"] = {1, false, "id", {"id"}};
    symbol2proto["_objc_release"] = {1, false, "id", {"id"}};
    symbol2proto["_objc_releaseAndReturn"] = {1, false, "id", {"id"}};
    symbol2proto["_objc_retainAutoreleaseAndReturn"] = {1, false, "id", {"id"}};
    symbol2proto["_objc_autoreleaseReturnValue"] = {1, false, "id", {"id"}};
    symbol2proto["_objc_retainAutoreleaseReturnValue"] = {1, false, "id", {"id"}};
    symbol2proto["_objc_retainAutoreleasedReturnValue"] = {1, false, "id", {"id"}};
    symbol2proto["_objc_retainAutorelease"] = {1, false, "id", {"id"}};
}

int SymbolWrapperScanner::start() {
    ScannerDisassemblyDriver *disasmDriver = this->driver;
    bool localDriver = false;
    if (!disasmDriver) {
        printf("\t[*] using local driver\n");
        disasmDriver = new ScannerDisassemblyDriver();
        localDriver = true;
    }
    
    const char *prepadding = localDriver ? "" : "    ";
    
    cout << prepadding << "[*] start Symbol Wrapper Scanner" << endl;
    
    if (options.find("symbols") == options.end()) {
        cout << termcolor::red;
        cout << StringUtils::format("%s[-] Error: you should specific symbols by -d 'symbols=<symbol>,<symbol>' or 'symbols=*'", prepadding);
        cout << termcolor::reset << endl;
        return 1;
    }
    
    string symbolsExpr = options["symbols"];
    set<string> symbols;
    if (symbolsExpr == "*") {
        for (auto it = symbol2proto.begin(); it != symbol2proto.end(); it++) {
            symbols.insert(it->first);
        }
    } else {
        vector<string> allSymbols = StringUtils::split(symbolsExpr, ',');
        set<string> _symbols(allSymbols.begin(), allSymbols.end());
        symbols = _symbols;
    }
    
    // setup recordPath
    string graphPath = StringUtils::path_join(outputPath, fileName + "_wrapper-graph.iblessing.txt");
    
    printf("%s  [*] try to find wrappers for", prepadding);
    bool first = true;
    for (string symbol : symbols) {
        printf("%s%s", first ? "" : ", ", symbol.c_str());
        first = false;
    }
    printf("\n");
    
    printf("%s  [*] Step1. find __TEXT,__text\n", prepadding);
    VirtualMemoryV2 *vm = VirtualMemoryV2::progressDefault();
    struct ib_section_64 *textSect = vm->getTextSect();
    vm->mappingMachOToEngine(uc, vm->getMappedFile());
    
    printf("%s  [*] Step 2. scan in __text\n", prepadding);
    uint64_t startAddr = textSect->addr;
    uint64_t endAddr = textSect->addr + textSect->size;
    uint64_t addrRange = endAddr - startAddr;
    uint8_t *codeData = vm->getMappedFile() + textSect->offset;
    printf("%s\t[*] start disassembler at 0x%llx\n", prepadding, startAddr);
    string last_mnemonic = "";
    char progressChars[] = {'\\', '|', '/', '-'};
#if 0
    uint64_t stub = 0x10038436C;
    codeData = codeData + stub - startAddr;
    startAddr = stub;
#endif
    
    funcStartCursor = startAddr;
    disasmDriver->subscribeDisassemblyEvent(this, [=](bool success, cs_insn *insn, bool *stop, ARM64PCRedirect **redirect) {
        SymbolTable *symtab = SymbolTable::getInstance();
#if 0
        if (!success) {
            cout << "\t[-]" << termcolor::yellow;
            cout << StringUtils::format(" an error occurred when disassemble at address 0x%llx", insn->address);
            cout << termcolor::reset << endl;
            return;
        }
#endif
        
        /**
         __text:00000001058C05B0                 MOV             X0, X19
         __text:00000001058C05B4                 MOV             X1, X21
         __text:00000001058C05B8                 B               objc_msgSend
         
         __text:00000001058C05BC                 STR             XZR, [SP,#arg_28]
         __text:00000001058C05C0                 MOV             X0, X22
         __text:00000001058C05C4                 MOV             X1, X20
         __text:00000001058C05C8                 B               objc_msgSend

         __text:00000001058C05CC                 MOV             X1, X21
         __text:00000001058C05D0                 B               objc_msgSend
         
         */
        
        // 1. mark B / RET / BRK as return
        // 2. short expr, scan objc_msgSend first, and trace back to return, find head (not more than 10 ins)
        // 3. go forward to objc_msgSend, record register transform
        if (strcmp(insn->mnemonic, "ret") == 0 ||
            strcmp(insn->mnemonic, "brk") == 0) {
            funcStartCursor = insn->address + 4;
            hasMemLoader = false;
            {
                AntiWrapperRegLinkGraph graph;
                currentGraph = graph;
            }
            return;
        }
        
        // handle mov actions
        if (strcmp(insn->mnemonic, "mov") == 0) {
            // MOV <Xd>, <Xm>
            cs_arm64 detail = insn[0].detail->arm64;
            cs_arm64_op src = detail.operands[0];
            cs_arm64_op dst = detail.operands[1];
            currentGraph.createLink(src, dst);
        }
        
        // record objc_msgSend, skip all bl
        if (strcmp(insn->mnemonic, "b") == 0) {
            uint64_t pc = insn[0].detail->arm64.operands[0].imm;
            Symbol *symbol = symtab->getSymbolByAddress(pc);
            if (symbol && symbols.find(symbol->name) != symbols.end()) {
                if (!hasMemLoader && insn->address > funcStartCursor && (insn->address - funcStartCursor) <= sizeof(uint32_t) * 10) {
//                    printf("[+] find wrapper for %s at 0x%llx\n", symbol->name.c_str(), funcStartCursor);
                    
                    AntiWrapperBlock block;
                    block.symbolName = symbol->name;
                    block.startAddr = funcStartCursor;
                    block.endAddr = insn->address;
                    block.regLinkGraph = currentGraph;
                    block.transformer = [=](AntiWrapperBlock block, AntiWrapperArgs args) {
                        pthread_mutex_lock(&wrapperLock);
                        uc_context_restore(uc, ctx);
                        for (int i = 0; i < args.nArgs; i++) {
                            if (i <= 28) {
                                uc_reg_write(uc, UC_ARM64_REG_X0 + i, &args.x[i]);
                            } else if (i <= 30) {
                                uc_reg_write(uc, UC_ARM64_REG_X29, &args.x[i]);
                            }
                        }
                        
                        uint64_t tmpBufSize = sizeof(uint32_t) * (block.endAddr - block.startAddr);
                        void *tmpBuf = malloc(tmpBufSize);
                        if (uc_mem_read(uc, block.startAddr, tmpBuf, tmpBufSize) != UC_ERR_OK) {
                            uc_mem_write(uc, block.startAddr, vm->getMappedFile() + block.startAddr - vm->getBaseAddr(), tmpBufSize);
                        }
                        free(tmpBuf);
                        
                        uc_err err = uc_emu_start(uc, block.startAddr, block.endAddr, 0, 100);
                        if (err) {
//                            printf("wrapper simulator uc error %s at 0x%llx\n", uc_strerror(err), block.startAddr);
                        }
                        uc_emu_stop(uc);
                        
                        pthread_mutex_unlock(&wrapperLock);
                        
                        for (int i = 0; i < args.nArgs; i++) {
                            if (i <= 28) {
                                uc_reg_read(uc, UC_ARM64_REG_X0 + i, &args.x[i]);
                            } else if (i <= 30) {
                                uc_reg_read(uc, UC_ARM64_REG_X29 + i - 29, &args.x[i]);
                            }
                        }
                        return args;
                    };
                    antiWrapper.setSimpleWrapper(block);
                    
#if 0
                    *stop = true;
#endif
                }
            }
            
            // it is return anyway
            funcStartCursor = insn->address + 4;
            hasMemLoader = false;
            {
                AntiWrapperRegLinkGraph graph;
                currentGraph = graph;
            }
        }
        
        if (strcmp(insn->mnemonic, "adrp") == 0 ||
            strcmp(insn->mnemonic, "str") == 0 ||
            strcmp(insn->mnemonic, "stp") == 0 ||
            strcmp(insn->mnemonic, "ldr") == 0 ||
            strcmp(insn->mnemonic, "ldp") == 0 ||
            strcmp(insn->mnemonic, "adr") == 0) {
            hasMemLoader = true;
        }
        
        if (localDriver) {
            float progress = 100.0 * (insn->address - startAddr) / addrRange;
#ifdef XcodeDebug
            static long _filter = 0;
            if (++_filter % 5000 == 0) {
                
#endif
            fprintf(stdout, "\r\t[*] %c 0x%llx/0x%llx (%.2f%%)", progressChars[progressCur], insn->address, endAddr, progress);
            fflush(stdout);
                
#ifdef XcodeDebug
            }
#endif

            progressCur = (++progressCur) % sizeof(progressChars);
        }
        
        if (*stop) {
            cout << prepadding << "\t[*] A total of ";
            cout << termcolor::green << antiWrapper.simpleWrapperMap.size();
            cout << termcolor::reset;
            cout << " wrappers were found" << endl;
            
            if (localDriver) {
                printf("\n%s  [*] Step 3. serialize wrapper graph to file\n", prepadding);
            }
            if (SymbolWrapperSerializationManager::createReportFromAntiWrapper(graphPath, antiWrapper, symbol2proto)) {
                printf("%s\t[*] wrapper graph file saved to %s\n", prepadding, graphPath.c_str());
            } else {
                printf("%s\t[*] error: cannot save to path %s\n", prepadding, graphPath.c_str());
            }
            
            printf("%s[*] Symbol Wrapper Scanner finished\n", prepadding);
        }
    });
    
    if (localDriver) {
        disasmDriver->startDisassembly(codeData, startAddr, endAddr);
        delete disasmDriver;
    } else {
        printf("%s\t[*] Wating for driver event\n", prepadding);
    }
    
    return 0;
}
