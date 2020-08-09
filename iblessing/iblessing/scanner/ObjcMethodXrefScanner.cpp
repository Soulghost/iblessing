//
//  ObjcMethodXrefScanner.cpp
//  iblessing
//
//  Created by soulghost on 2020/5/15.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcMethodXrefScanner.hpp"
#include "ObjcRuntime.hpp"
#include "VirtualMemory.hpp"
#include "termcolor.h"
#include "ARM64Runtime.hpp"
#include "SymbolTable.hpp"
#include "ARM64ThreadState.hpp"
#include "StringUtils.h"
#include <set>
#include <sstream>
#include <fstream>
#include <string>
#include "DyldSimulator.hpp"
#include <pthread.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include "SymbolWrapperScanner.hpp"
#include "SymbolXREFScanner.hpp"
#include "ScannerDispatcher.hpp"
#include "VirtualMemoryV2.hpp"
#include "ObjcMethodChainSerializationManager.hpp"

#define ClassAsInstanceTrickMask 0x0100000000000000
#define IvarInstanceTrickMask    0x1000000000000000
#define HeapInstanceTrickMask    0x2000000000000000
#define SelfInstanceTrickMask    0x4000000000000000
#define SelfSelectorTrickMask    0x8000000000000000

#define SubClassDummyAddress      0xcafecaaecaaecaae
#define ExternalClassDummyAddress 0xfacefacefaceface

//#define UsingSet
//#define DebugMethod "currentCameraPositionSubject"
//#define DebugTrackCall
//#define DebugClass  "AFCXbsManager"
//#define ThreadCount 8
//#define ShowFullLog 1
//#define TinyTest 100
//#define RecordPath "/Users/soulghost/Desktop/exploits/didi-iOS/iblessing_tracing_tinyx.txt"

using namespace std;
using namespace iblessing;

static string recordPath;
static SymbolWrapperScanner *antiWrapperScanner;
static uc_hook insn_hook, mem_hook, memexp_hook;

static map<string, MethodChain *> sel2chain;

static void trackCall(uc_engine *uc, ObjcMethod *currentMethod, uint64_t x0, uint64_t x1);
static void storeMethodChains();

static bool isValidClassInfo(ObjcClassRuntimeInfo *info) {
    return ObjcRuntime::getInstance()->isValidClassInfo(info);
}

static cs_insn* copy_insn(cs_insn *insn) {
    cs_insn *buffer = (cs_insn *)malloc(sizeof(cs_insn));
    memcpy(buffer, insn, sizeof(cs_insn));
    buffer->detail = (cs_detail *)malloc(sizeof(cs_detail));
    memcpy(buffer->detail, insn->detail, sizeof(cs_detail));
    return buffer;
}

static void free_insn(cs_insn *insn) {
    free(insn->detail);
    free(insn);
}

class EngineContext {
public:
    int identifer;
    uc_engine *engine;
    uint64_t lastPc;
    uc_context *defaultContext;
    csh disasmHandler;
    ObjcMethod *currentMethod;
    vector<ObjcMethod *> methods;
    
    // block status
    bool isInBlockBuilder;
    int blockValidElementCount;
    uint64_t blockIsaAddr;
    uint64_t blockInvokerAddr;
    uint64_t blockFlags;
    uint64_t blockDescAddr;
    uint64_t blockSize;
    
    // FIXME: trick for uc reg and capstone reg types
    cs_insn *lastInsn;
    
    void setLastInsn(cs_insn *insn) {
        if (lastInsn) {
            free_insn(lastInsn);
        }
        lastInsn = copy_insn(insn);
    }
};

static map<uc_engine *, EngineContext *> engineContexts;
static pthread_mutex_t globalMutex;
static pthread_mutex_t counterMutex;
static pthread_mutex_t indexMutex;
static uint64_t curCount = 0;
static uint64_t totalCount = 0;

static void finishBlockSession(EngineContext *ctx, uc_engine *uc) {
    if (!ctx->isInBlockBuilder) {
        return;
    }
    
    ctx->isInBlockBuilder = false;
    if (ctx->blockValidElementCount < 5) {
        return;
    }
    
    uint64_t blockStart = ctx->blockIsaAddr;
    void *blockBuffer = malloc(ctx->blockSize);
    if (UC_ERR_OK != uc_mem_read(uc, blockStart, blockBuffer, ctx->blockSize)) {
        return;
    }
    
    ObjcRuntime *rt = ObjcRuntime::getInstance();
    ObjcBlock *block = new ObjcBlock();
    block->stack = blockBuffer;
    block->stackSize = ctx->blockSize;
    block->invoker = ctx->blockInvokerAddr;
    
    // http://clang.llvm.org/docs/Block-ABI-Apple.html
    struct Block_literal_1 {
        void *isa; // initialized to &_NSConcreteStackBlock or &_NSConcreteGlobalBlock
        int flags;
        int reserved;
        void (*invoke)(void *, ...);
        struct Block_descriptor_1 {
            unsigned long int reserved;         // NULL
            unsigned long int size;         // sizeof(struct Block_literal_1)
            // optional helper functions
            void (*copy_helper)(void *dst, void *src);     // IFF (1<<25)
            void (*dispose_helper)(void *src);             // IFF (1<<25)
            // required ABI.2010.3.16
            const char *signature;                         // IFF (1<<30)
        } *descriptor;
        // imported variables
    };
    
#define BLOCK_HAS_COPY_DISPOSE   (1 << 25)
#define BLOCK_HAS_SIGNATURE      (1 << 30)
    
    uint64_t signatureOffsetInDesc = 0;
    if (ctx->blockFlags & BLOCK_HAS_SIGNATURE) {
        signatureOffsetInDesc = 16;
        if (ctx->blockFlags & BLOCK_HAS_COPY_DISPOSE) {
            signatureOffsetInDesc += (8 * 2);
        }
    }
    
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    if (signatureOffsetInDesc > 0) {
        uint64_t sigAddr = 0;
        if (UC_ERR_OK == uc_mem_read(uc, ctx->blockDescAddr + signatureOffsetInDesc, &sigAddr, 8)) {
            char *signature = vm2->readString(sigAddr, 1000);
            vector<string> parts;
            if (signature) {
                parts = StringUtils::split(signature, '@');
            }
            for (int i = 1; i < parts.size(); i++) {
                string &part = parts[i];
                if (i == 1) {
                    if (part == "?0") {
                        // common block
                        block->commonBlock = true;
                        continue;
                    } else {
                        block->commonBlock = false;
                    }
                }
                
                BlockVariable *blockVar = new BlockVariable();
                if (part.length() > 2 && part[0] == '"') {
                    stringstream ss;
                    ss << part[1];
                    for (int i = 2; i < part.length(); i++) {
                        char c = part[i];
                        if (c == '"') {
                            break;
                        }
                        ss << c;
                    }
                    string className = ss.str();
                    ObjcClassRuntimeInfo *classInfo = rt->getClassInfoByName(className);
                    if (classInfo) {
                        blockVar->type = BlockVariableTypeObjcClass;
                        blockVar->classInfo = classInfo;
                    } else {
                        blockVar->type = BlockVariableTypeUnknown;
                    }
                } else {
                    blockVar->type = BlockVariableTypePrimary;
                }
                block->args.push_back(blockVar);
            }
        }
    }
    
    
    rt->invoker2block[ctx->blockInvokerAddr] = block;
//    printf("[*] finish block with invoker addr 0x%llx\n", ctx->blockInvokerAddr);
}

static void startBlockSession(EngineContext *ctx, uc_engine *uc, cs_insn *insn) {
    if (ctx->isInBlockBuilder) {
        finishBlockSession(ctx, uc);
    }
    
    // detect str mem op
    cs_arm64 detail = ctx->lastInsn->detail->arm64;
    cs_arm64_op op = detail.operands[1];
    if (op.type == ARM64_OP_MEM) {
        arm64_reg base = op.mem.base;
        int32_t disp = op.mem.disp;
        uint64_t sp = 0;
        if (base == ARM64_REG_SP &&
            UC_ERR_OK == uc_reg_read(ctx->engine, UC_ARM64_REG_SP, &sp)) {
            uint64_t blockAddr = sp + disp;
//            printf("\n\t[~] find block build prologue at 0x%llx, block address on stack 0x%llx\n", ctx->lastInsn->address, blockAddr);
            
            ctx->isInBlockBuilder = true;
            ctx->blockIsaAddr = blockAddr;
            ctx->blockSize = 0x20;
        }
    }
}

static void insn_hook_callback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    void *codes = malloc(sizeof(uint32_t));
    uc_err err = uc_mem_read(uc, address, codes, sizeof(uint32_t));
    if (err != UC_ERR_OK) {
        free(codes);
        return;
    }
    
    SymbolTable *symtab = SymbolTable::getInstance();
    ObjcRuntime *rt = ObjcRuntime::getInstance();
    EngineContext *ctx = engineContexts[uc];
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    
    bool reachToEnd = false;
    cs_insn *insn = nullptr;
    size_t count = cs_disasm(ctx->disasmHandler, (uint8_t *)codes, 4, address, 0, &insn);
    if (count != 1) {
        if (insn && count > 0) {
            cs_free(insn, count);
        }
        free(codes);
        return;
    }
    
    // FIXME: loop trick
    // detect loop
    if (address <= ctx->lastPc) {
#if ShowFullLog
        printf("\t[*] Warn: detect loop, skip out\n");
#endif
        uint64_t pc = ctx->lastPc + size;
        assert(uc_reg_write(uc, UC_ARM64_REG_PC, &pc) == UC_ERR_OK);
        ctx->setLastInsn(insn);
        free(codes);
        cs_free(insn, count);
        return;
    }
    
    // detect return
    // FIXME: wrapped return, tiktok 0x1064B6A08
    if (ARM64Runtime::isRET(insn)) {
        reachToEnd = true;
        ctx->setLastInsn(insn);
        free(codes);
        cs_free(insn, count);
        uc_emu_stop(uc);
        finishBlockSession(ctx, uc);
        return;
    }
    
    // split at condition branch
    // FIXME: skip now
    if (strcmp(insn->mnemonic, "cbz") == 0 ||
        strcmp(insn->mnemonic, "cbnz") == 0) {
        // always jump to next ins
        uint64_t pc = address + size;
        assert(uc_reg_write(uc, UC_ARM64_REG_PC, &pc) == UC_ERR_OK);
    }
    
    // skip branches
    if (strncmp(insn->mnemonic, "b.", 2) == 0 ||
        strncmp(insn->mnemonic, "bl.", 3) == 0) {
        // always jump to next ins
        uint64_t pc = address + size;
        assert(uc_reg_write(uc, UC_ARM64_REG_PC, &pc) == UC_ERR_OK);
    }
    
    // skip blr
    if (strcmp(insn->mnemonic, "blr") == 0) {
        // always jump to next ins
        uint64_t pc = address + size;
        assert(uc_reg_write(uc, UC_ARM64_REG_PC, &pc) == UC_ERR_OK);
    }
    
    // detect block
    if (ctx->lastInsn) {
        // block capture, method only
        if (!ctx->currentMethod->classInfo->isSub &&
            strcmp(ctx->lastInsn->mnemonic, "str") == 0) {
            cs_arm64 detail = ctx->lastInsn->detail->arm64;
            uint64_t xn = 0;
            if (detail.operands[0].reg != ARM64_REG_INVALID &&
                UC_ERR_OK == uc_reg_read(ctx->engine, detail.operands[0].reg, &xn)) {
                if (rt->blockISAs.find(xn) != rt->blockISAs.end()) {
                    startBlockSession(ctx, uc, ctx->lastInsn);
                } else if (ctx->isInBlockBuilder) {
                    cs_arm64_op op = detail.operands[1];
                    if (op.type == ARM64_OP_MEM) {
                        arm64_reg base = op.mem.base;
                        int32_t disp = op.mem.disp;
                        uint64_t sp = 0;
                        if (base == ARM64_REG_SP &&
                            UC_ERR_OK == uc_reg_read(ctx->engine, UC_ARM64_REG_SP, &sp)) {
                            uint64_t targetAddr = sp + disp;
                            if (targetAddr == ctx->blockIsaAddr + 0x8) {
//                                    printf("\t[~] find block flags at 0x%llx, value 0x%llx\n", targetAddr, xn);
                                uc_mem_read(uc, targetAddr, &ctx->blockFlags, 4);
                                ctx->blockValidElementCount++;
                            } else if (targetAddr == ctx->blockIsaAddr + 0xc) {
//                                    printf("\t[~] find block reserved at 0x%llx, value 0x%llx\n", targetAddr, xn);
                                ctx->blockValidElementCount++;
                            } else if (targetAddr == ctx->blockIsaAddr + 0x10) {
//                                    printf("\t[~] find block invoker at 0x%llx, value 0x%llx\n", targetAddr, xn);
                                uc_mem_read(uc, targetAddr, &ctx->blockInvokerAddr, 8);
                                ctx->blockValidElementCount++;
                            } else if (targetAddr == ctx->blockIsaAddr + 0x18) {
//                                    printf("\t[~] find block desc at 0x%llx, value 0x%llx\n", targetAddr, xn);
                                uc_mem_read(uc, targetAddr, &ctx->blockDescAddr, 8);
                                ctx->blockValidElementCount++;
                            } else if (targetAddr >= ctx->blockIsaAddr + 0x20) {
//                                    printf("\t[~] may find capture var at 0x%llx, value 0x%llx\n", targetAddr, xn);
                                ctx->blockValidElementCount++;
                                // FIXME: trick capture size 0x8
                                if (ctx->blockSize < 0x1000) {
                                    ctx->blockSize += 0x8;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // record objc_msgSend, skip all bl
    if (strcmp(insn->mnemonic, "b") == 0 ||
        strcmp(insn->mnemonic, "bl") == 0) {
        uint64_t pc = insn[0].detail->arm64.operands[0].imm;
        bool isMsgSendOrWrapper = false;
        Symbol *symbol = symtab->getSymbolByAddress(pc);
        
        // string to class
        if (symbol && strcmp(symbol->name.c_str(), "_NSClassFromString") == 0) {
            // parse CFString
            uint64_t x0 = 0;
            uc_err err = uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
            if (err == UC_ERR_OK) {
                char *className = vm2->readAsCFStringContent(x0);
                if (className) {
                    uint64_t classAddr = rt->getClassAddrByName(className);
                    free(className);
                    if (classAddr) {
                        // write class addr to x0
                        uc_reg_write(uc, UC_ARM64_REG_X0, &classAddr);
                    }
                }
            }
        }
        
        // simulate runtime functions
        if (symbol && strcmp(symbol->name.c_str(), "_objc_storeStrong") == 0) {
#if 0
            void
            objc_storeStrong(id *location, id obj)
            {
                id prev = *location;
                if (obj == prev) {
                    return;
                }
                objc_retain(obj);
                *location = obj;
                objc_release(prev);
            }
#endif
            // check x1 and store to x0
            uint64_t x0, x1;
            if (UC_ERR_OK == uc_reg_read(uc, UC_ARM64_REG_X0, &x0) &&
                UC_ERR_OK == uc_reg_read(uc, UC_ARM64_REG_X1, &x1)) {
                uint64_t locationAddr = x0;
                uint64_t objAddr = x1;
                if (!ctx->isInBlockBuilder) {
                    uc_mem_write(uc, locationAddr, &objAddr, 8);
                } else if (objAddr != 0) {
                    // FIXME: dirty trick for block capture list release
                    uc_mem_write(uc, locationAddr, &objAddr, 8);
                }
            }
        }
        
        // allocate
        bool isAllocate = false;
        if (symbol && strcmp(symbol->name.c_str(), "_objc_alloc_init") == 0) {
            // simple allocate
            isAllocate = true;
        } else if (symbol && strcmp(symbol->name.c_str(), "_objc_alloc") == 0) {
            // custom init allocate
            isAllocate = true;
        } else if (symbol && strcmp(symbol->name.c_str(), "_objc_allocWithZone") == 0) {
            // FIXME: swift instance allocate
        }
        if (isAllocate) {
            // FIXME: x0 class structure validate
            uint64_t x0;
            uc_err err = uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
            if (err == UC_ERR_OK) {
                // FIXME: external class realize
                bool success = false;
                uint64_t classData = vm2->read64(x0, &success);
                if (success && classData) {
                    ObjcClassRuntimeInfo *classInfo = rt->getClassInfoByAddress(x0);
                    if (classInfo) {
                        uint64_t encodedAddr = classInfo->address | HeapInstanceTrickMask;
                        pthread_mutex_lock(&indexMutex);
                        rt->heapInstanceTrickAddress2RuntimeInfo[encodedAddr] = classInfo;
                        pthread_mutex_unlock(&indexMutex);
                        uc_reg_write(uc, UC_ARM64_REG_X0, &encodedAddr);
                    }
                }
            }
        }
        
        // [instance class]
        if (symbol && strcmp(symbol->name.c_str(), "_objc_opt_class") == 0) {
            uint64_t x0;
            assert(UC_ERR_OK == uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
            
            /**
                x0 = self => [self class]
                x0 = ivar => [ivar class]
                x0 = other instance => not support now
             */
            
            // this is a trick before method emu start (x0 = &classInfo)
            pthread_mutex_lock(&indexMutex);
            if (x0 & SelfInstanceTrickMask) {
//                    x0 = x0 & ~(SelfInstanceTrickMask);
                // self call, write self's real class addr to x0
                uc_reg_write(uc, UC_ARM64_REG_X0, &ctx->currentMethod->classInfo->address);
            } else if (rt->ivarInstanceTrickAddress2RuntimeInfo.find(x0) != rt->ivarInstanceTrickAddress2RuntimeInfo.end()) {
                // ivar instance, write ivar's real class addr to x0
                ObjcClassRuntimeInfo *ivarClassInfo = rt->ivarInstanceTrickAddress2RuntimeInfo[x0];
                uc_reg_write(uc, UC_ARM64_REG_X0, &ivarClassInfo->address);
            } else if (rt->heapInstanceTrickAddress2RuntimeInfo.find(x0) !=
                       rt->heapInstanceTrickAddress2RuntimeInfo.end()) {
                // heap instance from allocate
                ObjcClassRuntimeInfo *heapClassInfo = rt->heapInstanceTrickAddress2RuntimeInfo[x0];
                uc_reg_write(uc, UC_ARM64_REG_X0, &heapClassInfo->address);
            } else {
                // other instance: TODO
            }
            pthread_mutex_unlock(&indexMutex);
        }
        if (symbol && strcmp(symbol->name.c_str(), "_objc_msgSend") == 0) {
            isMsgSendOrWrapper = true;
        } else {
            if (antiWrapperScanner && antiWrapperScanner->antiWrapper.isWrappedCall(pc)) {
                AntiWrapperArgs args;
                args.nArgs = 31;
                for (int i = 0; i < 31; i++) {
                    if (i <= 28) {
                        uc_reg_read(uc, UC_ARM64_REG_X0 + i, &args.x[i]);
                    } else {
                        uc_reg_read(uc, UC_ARM64_REG_X29 + i - 29, &args.x[i]);
                    }
                }
                
                // we only take care of x0, x1, dont pollute other regs
                args = antiWrapperScanner->antiWrapper.performWrapperTransform(pc, args);
                for (int i = 0; i < 2; i++) {
                    uc_reg_write(uc, UC_ARM64_REG_X0 + i, &args.x[i]);
                }
                isMsgSendOrWrapper = true;
            }
        }
        
        if (isMsgSendOrWrapper) {
            uint64_t x0 = 0, x1 = 0;
            if (uc_reg_read(uc, UC_ARM64_REG_X0, &x0) == UC_ERR_OK &&
                uc_reg_read(uc, UC_ARM64_REG_X1, &x1) == UC_ERR_OK) {
                pthread_mutex_lock(&globalMutex);
#ifdef DebugTrackCall
                printf("[****] |--- 0x%llx\n", insn->address);
#endif
                // error at 0x00000001003b4884
                trackCall(uc, ctx->currentMethod, x0, x1);
                pthread_mutex_unlock(&globalMutex);
            } else {
                cout << termcolor::yellow;
                cout << StringUtils::format("\t[+] failed to resolve objc_msgSend at 0x%llx\n", insn->address);
                cout << termcolor::reset << endl;
            }
        }
        // jump to next ins
        pc = address + size;
        assert(uc_reg_write(uc, UC_ARM64_REG_PC, &pc) == UC_ERR_OK);
//            finishBlockSession(ctx, uc);
    }

    ctx->setLastInsn(insn);
    free(codes);
    cs_free(insn, count);
    ctx->lastPc = address;
}

static void mem_hook_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
}

static bool mem_exception_hook_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
//    printf("[----------------] mem error %d 0x%llx %d !!!\n", type, address, size);
    return true;
}

void* pthread_uc_worker(void *ctx) {
    EngineContext *context = reinterpret_cast<EngineContext *>(ctx);
    ObjcRuntime *rt = ObjcRuntime::getInstance();
    for (size_t i = 0; i < context->methods.size(); i++) {
#if ShowFullLog
        printf("\t[*] thread %d: current method index %zu / %zu\n", context->identifer, i, context->methods.size() - 1);
#else
//        if (i % 10000 == 0) {
//            printf("\t[*] current method index %zu / %lu\n", i, methods.size());
//        }
#endif
        ObjcMethod *m = context->methods[i];
        context->currentMethod = m;
//        printf("[*] trace method at index %zu\n", i);
        uc_context_restore(context->engine, context->defaultContext);
        context->lastPc = 0;
        context->isInBlockBuilder = false;
        context->blockIsaAddr = 0;
        context->lastInsn = nullptr;
        context->blockValidElementCount = 0;
        
        if (!m->classInfo->isSub) {
            // init x0 as classref
            uint64_t selfTrickAddr = ((uint64_t)m->classInfo) | SelfInstanceTrickMask;
            uc_reg_write(context->engine, UC_ARM64_REG_X0, &selfTrickAddr);
            
            // init x1 as SEL, faked as self class info
            uint64_t selfSELAddr = ((uint64_t)m->classInfo) | SelfSelectorTrickMask;
            uc_reg_write(context->engine, UC_ARM64_REG_X1, &selfSELAddr);
        } else {
            if (rt->invoker2block.find(m->imp) != rt->invoker2block.end()) {
                ObjcBlock *block = rt->invoker2block[m->imp];
                uint64_t blockBase = 0x200000000;
                
                // mapping block object to heap and set pointer
                if (UC_ERR_OK != uc_reg_write(context->engine, UC_ARM64_REG_X0, &blockBase) ||
                    UC_ERR_OK != uc_mem_write(context->engine, blockBase, block->stack, block->stackSize)) {
                    // error -_-
                }
                
                // set block args
                for (int i = 0; i < std::min((int)block->args.size(), 8); i++) {
                    BlockVariable *blockVar = block->args[i];
                    if (blockVar->type == BlockVariableTypeObjcClass) {
                        uint64_t encodedAddr = (uint64_t)blockVar->classInfo;
                        encodedAddr = encodedAddr | ClassAsInstanceTrickMask;
                        uc_reg_write(context->engine, UC_ARM64_REG_X1 + i, &encodedAddr);
                    }
                }
            }
        }
        
#ifdef DebugTrackCall
        printf("\n[****] start ana method %s %s, set classInfo at %p\n", m->classInfo->className.c_str(), m->name.c_str(), m->classInfo);
#endif
        uc_err err = uc_emu_start(context->engine, m->imp, 0, 0, 0);
        if (err != UC_ERR_OK) {
//            printf("\t[*] uc error %s\n", uc_strerror(err));
//            assert(0);
        }
        uc_emu_stop(context->engine);
        
        pthread_mutex_lock(&counterMutex);
        curCount += 1;
#ifndef XcodeDebug
        fprintf(stdout, "\r\t[*] progress: %lld / %lld (%.2f%%)", curCount, totalCount, 100.0 * curCount / totalCount);
        fflush(stdout);
#else
        if (curCount % 1000 == 0) {
            fprintf(stdout, "\r\t[*] progress: %lld / %lld (%.2f%%)", curCount, totalCount, 100.0 * curCount / totalCount);
            fflush(stdout);
        }
#endif
        pthread_mutex_unlock(&counterMutex);
    }
    return nullptr;
}

void trace_all_methods(vector<uc_engine *> engines, vector<ObjcMethod *> &methods, uint64_t cursor) {
#ifdef DebugMethod
    {
        vector<ObjcMethod *> m2;
        for (ObjcMethod *method : methods) {
            if (method->name == DebugMethod) {
                m2.push_back(method);
            }
        }
        methods = m2;
    }
#endif
    
    // split methods by engines
    uint64_t groupCount = engines.size();
    uint64_t methodCount = methods.size();
    if (methodCount < groupCount) {
        groupCount = methodCount;
        cout << termcolor::yellow;
        cout << StringUtils::format("\t[+] Warn: method count %llu less than thread count %llu", methodCount, groupCount);
        cout << termcolor::reset << endl;
    }
    uint64_t groupCap = methodCount / groupCount;
    curCount = 0;
    totalCount = methodCount;
    
    // create global lock
    pthread_mutexattr_t attr = {0};
    assert(pthread_mutexattr_init(&attr) == 0);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    assert(pthread_mutex_init(&globalMutex, &attr) == 0);
    assert(pthread_mutex_init(&counterMutex, &attr) == 0);
    assert(pthread_mutex_init(&indexMutex, &attr) == 0);
    
    // create threads
    vector<pthread_t> threads;
    
    size_t startIdx = 0;
    for (size_t i = 0; i < groupCount; i++) {
        EngineContext *ctx = engineContexts[engines[i]];
        auto endIt = __builtin_expect(i == groupCount - 1, false) ? methods.end() : methods.begin() + startIdx + groupCap;
        vector<ObjcMethod *> workMethods(methods.begin() + startIdx, endIt);
        ctx->methods = workMethods;
        startIdx += groupCap;
        
        pthread_t thread;
        assert(pthread_create(&thread, nullptr, pthread_uc_worker, (void *)ctx) == 0);
        threads.push_back(thread);
    }
    
    for (pthread_t t : threads) {
        pthread_join(t, NULL);
    }
    
    printf("\n");
    storeMethodChains();
}

uc_engine* createEngine(int identifier) {
    VirtualMemory *vm = VirtualMemory::progressDefault();
    uc_engine *uc;
    uc_context *ctx;
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("\t[-] error: %s\n", uc_strerror(err));
        return NULL;
    }
    
    // add hooks
    uc_hook_add(uc, &insn_hook, UC_HOOK_CODE, (void *)insn_hook_callback, NULL, 1, 0);
    uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_VALID, (void *)mem_hook_callback, NULL, 1, 0);
    uc_hook_add(uc, &memexp_hook, UC_HOOK_MEM_INVALID, (void *)mem_exception_hook_callback, NULL, 1, 0);
    
    // mapping 12GB memory region, first 4GB is PAGEZERO
    // ALL       0x000000000 ~ 0x300000000
    // PAGE_ZERO 0x000000000 ~ 0x100000000
    // HEAP      0x100000000 ~ 0x300000000
    // STACK     ?           ~ 0x300000000
    uint64_t unicorn_vm_size = 12L * 1024 * 1024 * 1024;
    uint64_t unicorn_vm_start = 0;
    assert(uc_mem_map(uc, unicorn_vm_start, unicorn_vm_size, UC_PROT_ALL) == UC_ERR_OK);
    // FIXME: failed condition
    assert(uc_mem_write(uc, vm->vmaddr_base, vm->mappedFile, vm->mappedSize) == UC_ERR_OK);
    
    // setup default thread state
    assert(uc_context_alloc(uc, &ctx) == UC_ERR_OK);
    
    uint64_t unicorn_sp_start = 0x300000000;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    uc_context_save(uc, ctx);
    
    // create disasm handle
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    // build context
    EngineContext *engineCtx = new EngineContext();
    engineCtx->identifer = identifier;
    engineCtx->engine = uc;
    engineCtx->disasmHandler = handle;
    engineCtx->defaultContext = ctx;
    engineCtx->lastPc = 0;
    engineCtx->currentMethod = NULL;
    engineContexts[uc] = engineCtx;
    return uc;
}

int ObjcMethodXrefScanner::start() {
    printf("[*] start ObjcMethodXrefScanner Exploit Scanner\n");
    vector<uc_engine *> engines;
    for (int i = 0; i < jobs; i++) {
        engines.push_back(createEngine(i));
    }
    
    printf("  [*] Step 1. realize all app classes\n");
    ObjcRuntime *rt = ObjcRuntime::getInstance();
    SymbolTable *symtab = SymbolTable::getInstance();
    VirtualMemory *vm = VirtualMemory::progressDefault();
    unordered_map<string, uint64_t> &classList = rt->classList;
    uint64_t count = 0, total = classList.size();
#if TinyTest
    uint64_t realize_limit = std::min((uint64_t)classList.size(), (uint64_t)TinyTest);
#endif
    vector<ObjcMethod *> methods;
    set<uint64_t> impAddrs;
    for (auto it = classList.begin(); it != classList.end(); it++) {
#if TinyTest
        if (realize_limit-- == 0) {
            break;
        }
#endif
        if (it->second == 0) {
            printf("\t[+] skip bad class %s\n", it->first.c_str());
        }
        ObjcClassRuntimeInfo *classInfo = rt->getClassInfoByAddress(it->second);
//        printf("\t[+] realize class %s, method count %lu\n", classInfo->className.c_str(), classInfo->methodList.size());
#ifdef DebugClass
        if (classInfo->className != DebugClass) {
            continue;
        } else {
            printf("\t[++] find debug class %s\n", DebugClass);
        }
#endif
        Vector<ObjcMethod *> allMethods = classInfo->getAllMethods();
        methods.insert(methods.end(), allMethods.begin(), allMethods.end());
        for (ObjcMethod *m : allMethods) {
            impAddrs.insert(m->imp);
        }
        count++;
#ifndef XcodeDebug
        fprintf(stdout, "\r\t[*] realize classes %lld/%lld (%.2f%%)", count, total, 100.0 * count / total);
        fflush(stdout);
#else
        if (count % 1000 == 0) {
            fprintf(stdout, "\r\t[*] realize classes %lld/%lld (%.2f%%)", count, total, 100.0 * count / total);
            fflush(stdout);
        }
#endif
    }
    printf("\n");
    printf("\t[+] get %lu methods to analyze\n", methods.size());
    
    
    printf("  [*] Step 2. Start sub-scanners\n");
    ScannerDisassemblyDriver *sharedDriver = new ScannerDisassemblyDriver();
    if (options.find("antiWrapper") != options.end()) {
        ScannerDispatcher *dispatcher = reinterpret_cast<ScannerDispatcher *>(this->dispatcher);
        options["symbols"] = "_objc_msgSend";
        Scanner *s = dispatcher->prepareForScanner("symbol-wrapper", options, inputPath, outputPath, sharedDriver);
        if (s) {
            antiWrapperScanner = reinterpret_cast<SymbolWrapperScanner *>(s);
            antiWrapperScanner->start();
        }
        cout << termcolor::yellow << "    [!] Warning: the anti-wrapper mode consumes a huge amount of memory,";
        cout << " this may be related to a memory leak or emulator problem, and I haven't solved it yet";
        cout << termcolor::reset << endl;
    } else {
        antiWrapperScanner = nullptr;
    }
    
    recordPath = StringUtils::path_join(outputPath, fileName + "_method-xrefs.iblessing.txt");
    
    SymbolXREFScanner *sxrefScanner = nullptr;
    ScannerDispatcher *dispatcher = reinterpret_cast<ScannerDispatcher *>(this->dispatcher);
    options["symbols"] = "_objc_msgSend";
    Scanner *s = dispatcher->prepareForScanner("symbol-xref", options, inputPath, outputPath, sharedDriver);
    if (s) {
        sxrefScanner = reinterpret_cast<SymbolXREFScanner *>(s);
        sxrefScanner->start();
    } else {
        cout << termcolor::red << "    [-] Error: cannot find symbol-xref scanner";
        cout << termcolor::reset << endl;
        return 1;
    }
    
    printf("    [*] Dispatching Disassembly Driver\n");
    struct ib_section_64 *textSect = vm->textSect;
    uint64_t startAddr = textSect->addr;
    uint64_t endAddr = textSect->addr + textSect->size;
    uint64_t addrRange = endAddr - startAddr;
    uint8_t *codeData = vm->mappedFile + textSect->offset;
    string last_mnemonic = "";
    char progressChars[] = {'\\', '|', '/', '-'};
    uint8_t progressCur = 0;
    sharedDriver->startDisassembly(codeData, startAddr, endAddr, [&](bool success, cs_insn *insn, bool *stop, ARM64PCRedirect **redirect) {
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
    });
    
    printf("  [*] Step 3. Create Common ClassInfo for subs and add to analysis list\n");
    // create common classInfo for subs
    ObjcClassRuntimeInfo *subClassInfo = new ObjcClassRuntimeInfo();
    subClassInfo->address = SubClassDummyAddress;
    subClassInfo->isExternal = true;
    subClassInfo->isSub = true;
    subClassInfo->className = StringUtils::format("iblessing_SubClass");
    for (auto it = sxrefScanner->xrefs.begin(); it != sxrefScanner->xrefs.end(); it++) {
        for (SymbolXREF sxref : it->second) {
            if (impAddrs.find(sxref.startAddr) != impAddrs.end()) {
                // skip imp
                continue;
            }
            
            // find a sub
            ObjcMethod *subMethod = new ObjcMethod();
            subMethod->classInfo = subClassInfo;
            subMethod->isClassMethod = true;
            subMethod->imp = sxref.startAddr;
            subMethod->name = StringUtils::format("sub_0x%llx", sxref.startAddr);
            methods.push_back(subMethod);
        }
    }
    delete sxrefScanner;
    
    printf("  [*] Step 4. dyld load non-lazy symbols\n");
    DyldSimulator::eachBind(vm->mappedFile, vm->segmentHeaders, vm->dyldinfo, [&](uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, uint64_t libraryOrdinal, const char *msg) {
        uint64_t symbolAddr = addr + addend;
        
        // load non-lazy symbols
        for (uc_engine *uc : engines) {
            uc_mem_write(uc, symbolAddr, &symbolAddr, 8);
        }
        
        // record class info
        if (string(symbolName).rfind("_OBJC_CLASS_$") == 0) {
            ObjcClassRuntimeInfo *externalClassInfo = new ObjcClassRuntimeInfo();
            externalClassInfo->isExternal = true;
            
            vector<string> parts = StringUtils::split(symbolName, '_');
            if (parts.size() > 1) {
                externalClassInfo->className = parts[parts.size() - 1];
            } else {
                externalClassInfo->className = symbolName;
            }
            rt->externalClassRuntimeInfo[symbolAddr] = externalClassInfo;
            rt->runtimeInfo2address[externalClassInfo] = symbolAddr;
        } else if (strcmp(symbolName, "__NSConcreteGlobalBlock") == 0 ||
                   strcmp(symbolName, "__NSConcreteStackBlock") == 0) {
            rt->blockISAs.insert(symbolAddr);
        }
        
        // record symbol
        Symbol *sym = new Symbol();
        sym->name = symbolName;
        struct ib_nlist_64 *nl = (struct ib_nlist_64 *)calloc(1, sizeof(ib_nlist_64));
        nl->n_value = symbolAddr;
        sym->info = nl;
        symtab->insertSymbol(sym);
//        vm->writeBySize(new uint64_t(symbolAddr), symbolAddr, 8, MemoryUnit::MemoryType::Common);
    });
    
    // remove dupliate elements
    methods.erase(unique(methods.begin(), methods.end(), [](ObjcMethod *a, ObjcMethod *b) {
        return a->imp == b->imp;
    }), methods.end());
    
    printf("  [*] Step 5. track all calls\n");
    trace_all_methods(engines, methods, 0);
    
    if (antiWrapperScanner) {
        delete antiWrapperScanner;
    }
    printf("  [*] ObjcMethodXrefScanner Exploit Scanner finished\n");
    return 0;
}

static void trackCall(uc_engine *uc, ObjcMethod *currentMethod, uint64_t x0, uint64_t x1) {
    ObjcRuntime *rt = ObjcRuntime::getInstance();
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    
    uint64_t instanceAddr = 0;
    const char *methodPrefix = "?";
    ObjcClassRuntimeInfo *detectedClassInfo = nullptr;
    const char *detectedSEL = "?";
#ifdef DebugTrackCall
    printf("[****] |--- trackCall %s %s, x0=0x%llx, x1=0x%llx\n", currentMethod->classInfo->className.c_str(), currentMethod->name.c_str(), x0, x1);
#endif
    
    // read sel
    if (x1) {
        // FIXME: x1 trick at method prologue
        if (x1 & SelfSelectorTrickMask) {
            detectedSEL = currentMethod->name.c_str();
        } else {
            detectedSEL = vm2->readString(x1, 255);
        }
    }
    
    if (detectedSEL == NULL) {
        // FIXME: some bug
        return;
    }
    
    if (x0) {
        uint64_t addr = x0;
        instanceAddr = addr;
        if (x0 & SelfInstanceTrickMask) {
            // self call -[self foo]
            detectedClassInfo = reinterpret_cast<ObjcClassRuntimeInfo *>(x0 & (~SelfInstanceTrickMask));
            methodPrefix = "-";
        } else if (x0 & ClassAsInstanceTrickMask) {
            detectedClassInfo = reinterpret_cast<ObjcClassRuntimeInfo *>(x0 & (~ClassAsInstanceTrickMask));
            methodPrefix = "-";
        } else if (rt->address2RuntimeInfo.find(addr) != rt->address2RuntimeInfo.end()) {
            // +[Class foo]
            detectedClassInfo = rt->address2RuntimeInfo[addr];
            methodPrefix = "+";
        } else if (rt->externalClassRuntimeInfo.find(addr) != rt->externalClassRuntimeInfo.end()) {
            // +[Class foo]
            detectedClassInfo = rt->externalClassRuntimeInfo[addr];
            methodPrefix = "+";
        } else if (rt->ivarInstanceTrickAddress2RuntimeInfo.find(addr) != rt->ivarInstanceTrickAddress2RuntimeInfo.end()) {
            // -[self.ivar foo]
            detectedClassInfo = rt->ivarInstanceTrickAddress2RuntimeInfo[addr];
            methodPrefix = "-";
        } else if (rt->heapInstanceTrickAddress2RuntimeInfo.find(addr) !=
                   rt->heapInstanceTrickAddress2RuntimeInfo.end()) {
            // -[instance foo]
            detectedClassInfo = rt->heapInstanceTrickAddress2RuntimeInfo[addr];
            methodPrefix = "-";
        } else {
            // try to reveal in symbol table (x0 = class-ref, class method call)
            // +[unknown_class foo]
            Symbol *sym = SymbolTable::getInstance()->getSymbolByAddress(addr);
            if (sym &&
                sym->name.rfind("_OBJC_") != -1 &&
                sym->name.rfind("_$_") != -1) {
                ObjcClassRuntimeInfo *externalInfo = new ObjcClassRuntimeInfo();
                externalInfo->address = ExternalClassDummyAddress;
                externalInfo->isExternal = true;
                externalInfo->className = StringUtils::split(sym->name, '$')[1].substr(1);
                detectedClassInfo = externalInfo;
                methodPrefix = "+";
            }
        }
    }
    
    // detected classInfo validation
    if (!isValidClassInfo(detectedClassInfo)) {
        detectedClassInfo = nullptr;
    }
    
    // deprecated, replaced by objc_opt_class
    if (strcmp(detectedSEL, "class") == 0 && detectedClassInfo) {
        // -[instance class] => x0 = instance.class_addr
        uc_reg_write(uc, UC_ARM64_REG_X0, &detectedClassInfo->address);
    }
    
    // detect +[Class new]
    if (strcmp(detectedSEL, "new") == 0 && detectedClassInfo) {
        bool success;
        uint64_t classData = vm2->read64(x0, &success);
        if (success && classData) {
            ObjcClassRuntimeInfo *classInfo = rt->getClassInfoByAddress(x0);
            if (classInfo) {
                uint64_t encodedAddr = classInfo->address | HeapInstanceTrickMask;
                pthread_mutex_lock(&indexMutex);
                rt->heapInstanceTrickAddress2RuntimeInfo[encodedAddr] = classInfo;
                pthread_mutex_unlock(&indexMutex);
                uc_reg_write(uc, UC_ARM64_REG_X0, &encodedAddr);
            }
        }
    }
    
    string classExpr;
    if (detectedClassInfo) {
        classExpr = detectedClassInfo->className;
    } else if (instanceAddr) {
        classExpr = StringUtils::format("0x%llx", instanceAddr);
    } else {
        classExpr = "?";
    }
    
    // eval ivar method
    if (detectedClassInfo && isValidClassInfo(detectedClassInfo) && detectedSEL) {
        ObjcClassRuntimeInfo *ivarClassInfo = rt->evalReturnForIvarGetter(detectedClassInfo, detectedSEL);
        if (ivarClassInfo) {
            // FIXME: ivar class addr trick mask
            uint64_t encodedTrickAddr = ivarClassInfo->address | IvarInstanceTrickMask;
            rt->ivarInstanceTrickAddress2RuntimeInfo[encodedTrickAddr] = ivarClassInfo;
            uc_reg_write(uc, UC_ARM64_REG_X0, &encodedTrickAddr);
        }
    }
    
    // indexing
    
#if 0
    // 1. [methods] <-> method <-> [methods]
    struct method_chain {
        vector<method_chain> prev_methods;
        vector<method_chain> next_methods;
    }
    
    // 2. SEL -> method
    map<SEL, method_chain>
    
    // 3. how to build it?
    // for method a, we can find trace a->b
    // mark a as current_chain
    // mark b as next_chain
    map[a] = make_chain(a)
    map[b] = make_chain(b)
    map[a]->next_methods.push_back(map[b])
    map[b]->prev_methods.push_back(map[a])
#endif
    
    string currentMethodExpr = StringUtils::format("%s[%s %s]",
                                                   currentMethod->isClassMethod ? "+" : "-",
                                                   currentMethod->classInfo->className.c_str(),
                                                   currentMethod->name.c_str()
                                                   );
    string followingMethodExpr = StringUtils::format("%s[%s %s]",
                                                   methodPrefix,
                                                   classExpr.c_str(),
                                                   detectedSEL
                                                   );
    
#ifdef DebugTrackCall
    if (-1 != classExpr.rfind("[") ||
        -1 != classExpr.rfind("]") ||
        -1 != classExpr.rfind("-") ||
        -1 != classExpr.rfind("+") ||
        -1 != currentMethod->classInfo->className.rfind("[") ||
        -1 != currentMethod->classInfo->className.rfind("]") ||
        -1 != currentMethod->classInfo->className.rfind("+") ||
        -1 != currentMethod->classInfo->className.rfind("-")) {
//        assert(false);
        printf("[****] |--- !!! bad classExpr %s\n", classExpr.c_str());
    }
#endif
    
    // add current method to chain if needed
    // FIXME: a sub call can only be root chain (currentMethod) now
    if (sel2chain.find(currentMethodExpr) == sel2chain.end()) {
        MethodChain *chain = new MethodChain();
        chain->impAddr = currentMethod->imp;
        chain->prefix = currentMethod->isClassMethod ? "+" : "-";
        chain->className = currentMethod->classInfo->className;
        chain->methodName = currentMethod->name;
        sel2chain[currentMethodExpr] = chain;
    }
    
    // add following method to chain if needed
    if (sel2chain.find(followingMethodExpr) == sel2chain.end()) {
        MethodChain *chain = new MethodChain();
        chain->impAddr = 0;
        chain->prefix = methodPrefix;
        chain->className = classExpr;
        chain->methodName = detectedSEL;
        sel2chain[followingMethodExpr] = chain;
        
        uint64_t targetClassAddr = rt->getClassAddrByName(classExpr);
        if (targetClassAddr > 0) {
            ObjcClassRuntimeInfo *info = rt->getClassInfoByAddress(targetClassAddr);
            ObjcMethod *m = info->getMethodBySEL(detectedSEL);
            if (m) {
                chain->impAddr = m->imp;
            }
        }
    }
    
    // caller pc (xref pc)
    uint64_t pc = 0;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    
    MethodChain *currentChain = sel2chain[currentMethodExpr];
    MethodChain *followingChain = sel2chain[followingMethodExpr];
    currentChain->nextMethods.insert({followingChain, pc});
    followingChain->prevMethods.insert({currentChain, pc});
    
#if ShowFullLog
    printf("[+] find trace %s (0x%llx) -> %s (0x%llx)\n", currentMethodExpr.c_str(), currentChain->impAddr, followingMethodExpr.c_str(), followingChain->impAddr);
#endif
}

static void storeMethodChains() {
    printf("  [*] Step 6. serialize call chains to file\n");
    if (ObjcMethodChainSerializationManager::storeMethodChain(recordPath, sel2chain)) {
        printf("\t[*] saved to %s\n", recordPath.c_str());
    } else {
        printf("\t[*] error: cannot save to path %s\n", recordPath.c_str());
    }
}


