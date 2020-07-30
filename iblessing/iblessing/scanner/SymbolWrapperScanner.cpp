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
#include "VirtualMemory.hpp"
#include "SymbolTable.hpp"
#include "termcolor.h"
#include "StringUtils.h"
#include "SymbolWrapperSerializationManager.hpp"
#include <set>

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
    
    uint64_t unicorn_sp_start = 0x1fffffff;
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
    cout << "[*] start Symbol Wrapper Scanner" << endl;
    
    if (options.find("symbols") == options.end()) {
        cout << termcolor::red;
        cout << StringUtils::format("Error: you should specific symbols by -d 'symbols=<symbol>,<symbol>' or 'symbols=*'");
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
    
    printf("  [*] try to find wrappers for");
    bool first = true;
    for (string symbol : symbols) {
        printf("%s%s", first ? "" : ", ", symbol.c_str());
        first = false;
    }
    printf("\n");
    
    printf("  [*] Step1. find __TEXT,__text\n");
    VirtualMemory *vm = VirtualMemory::progressDefault();
    struct section_64 *textSect = nullptr;
    struct segment_command_64 *textSeg = nullptr;
    for (struct segment_command_64 *seg : vm->segmentHeaders) {
        if (strncmp(seg->segname, "__TEXT", 16) == 0) {
            textSeg = seg;
            struct section_64 *sect = (struct section_64 *)((uint8_t *)seg + sizeof(struct segment_command_64));
            if (strncmp(sect->sectname, "__text", 16) == 0) {
                textSect = sect;
                break;
            }
        }
    }
    if (!textSect) {
        cout << "\t" << termcolor::red << "[-] Error: cannot find __TEXT,__text section";
        cout << termcolor::reset << endl;
        return 1;
    }
    printf("\t[+] find __TEXT,__text at 0x%llx\n", textSect->addr);
    assert(UC_ERR_OK == uc_mem_map(uc, textSeg->vmaddr, textSeg->vmsize, UC_PROT_READ | UC_PROT_EXEC));
    assert(UC_ERR_OK == uc_mem_write(uc, textSeg->vmaddr, vm->mappedFile + textSeg->fileoff, textSeg->vmsize));
    printf("\t[+] mapping text segment 0x%llx ~ 0x%llx to unicorn engine", textSeg->vmaddr, textSeg->vmaddr + textSeg->vmsize);
    
    printf("\n  [*] Step 2. scan in __text\n");
    uint64_t funcStartCursor = 0;
#if 1
    ARM64Disassembler *disasm = new ARM64Disassembler();
    uint64_t startAddr = textSect->addr;
    uint64_t endAddr = textSect->addr + textSect->size;
    uint64_t addrRange = endAddr - startAddr;
    uint8_t *codeData = vm->mappedFile + textSect->offset;
    printf("\t[*] start disassembler at 0x%llx\n", startAddr);
    string last_mnemonic = "";
    char progressChars[] = {'\\', '|', '/', '-'};
    uint8_t progressCur = 0;
#if 0
    uint64_t stub = 0x10038436C;
    codeData = codeData + stub - startAddr;
    startAddr = stub;
#endif
    
    SymbolTable *symtab = SymbolTable::getInstance();
    bool hasMemLoader = false;
    funcStartCursor = startAddr;
    AntiWrapperRegLinkGraph currentGraph;
    disasm->startDisassembly(codeData, startAddr, [&](bool success, cs_insn *insn, bool *stop, ARM64PCRedirect **redirect) {
        if (insn->address >= endAddr) {
            printf("\n\t[*] reach to end of __text, stop\n");
            *stop = true;
            return;
        }
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
            AntiWrapperRegLinkGraph newGraph;
            currentGraph = newGraph;
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
                    block.transformer = [&](AntiWrapperBlock block, AntiWrapperArgs args) {
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
                            uc_mem_write(uc, block.startAddr, vm->mappedFile + block.startAddr - vm->vmaddr_base, tmpBufSize);
                        }
                        free(tmpBuf);
                        
                        uc_err err = uc_emu_start(uc, block.startAddr, block.endAddr, 0, 100);
                        if (err) {
//                            printf("wrapper simulator uc error %s at 0x%llx\n", uc_strerror(err), block.startAddr);
                        }
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
                
                // it is return anyway
                funcStartCursor = insn->address + 4;
                hasMemLoader = false;
                {
                    AntiWrapperRegLinkGraph newGraph;
                    currentGraph = newGraph;
                }
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
#if 1
        float progress = 100.0 * (insn->address - startAddr) / addrRange;
        fprintf(stdout, "\r\t[*] %c 0x%llx/0x%llx (%.2f%%)", progressChars[progressCur], insn->address, endAddr, progress);
        fflush(stdout);
        progressCur = (++progressCur) % sizeof(progressChars);
#endif
    });
    delete disasm;
#endif
    
    // play a transform
#if 0
    uint64_t wrapperAddr = 0x1000221B0;
    AntiWrapperArgs args;
    args.x[0] = 0xaaaaaaaa;
    args.x[1] = 0xbbbbbbbb;
    args.x[20] = 0xfadeface;
    args.nArgs = 21;
    args = antiWrapper.performWrapperTransform(wrapperAddr, args);
    printf("the x0 0x%llx, x1 0x%llx\n", args.x[0], args.x[1]);
#endif
    
    printf("\n  [*] Step 3. serialize wrapper graph to file\n");
    if (SymbolWrapperSerializationManager::createReportFromAntiWrapper(graphPath, antiWrapper, symbol2proto)) {
        printf("\t[*] saved to %s\n", graphPath.c_str());
    } else {
        printf("\t[*] error: cannot save to path %s\n", graphPath.c_str());
    }
    return 0;
}
