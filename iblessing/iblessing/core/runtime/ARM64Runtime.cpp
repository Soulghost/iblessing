//
//  ARM64Runtime.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ARM64Runtime.hpp"
#include "VirtualMemory.hpp"
#include "VirtualMemoryV2.hpp"
#include "ARM64ThreadState.hpp"
#include "StringUtils.h"
#include "SymbolTable.hpp"

#define ASMAssert(cond, fatal) do {\
    if (!(cond)) { \
        if (fatal) { \
            assert(false);\
        } \
        return false; \
    } \
} while(0);

using namespace std;
using namespace iblessing;

bool ARM64Runtime::handleInstruction(cs_insn *insn, string *insnDesc, string *insnComment, bool fatal) {
    // analyzer
    string analyzeDesc = "";
    const char *mnemonic = insn[0].mnemonic;
    
    if (insnDesc) {
        *insnDesc = StringUtils::format("__text:%016llx %s\t%s", insn->address, insn->mnemonic, insn->op_str);
    }
    
    if (strcmp(mnemonic, "str") == 0 ||
        strcmp(mnemonic, "stur") == 0) {
        return handleSTR(insn, insnDesc, insnComment, fatal);
    }
    if (strcmp(mnemonic, "stp") == 0) {
        return handleSTP(insn, insnDesc, insnComment, fatal);
    }
    if (strcmp(mnemonic, "add") == 0) {
        return handleADD(insn, insnDesc, insnComment, fatal);
    }
    if (strcmp(mnemonic, "adrp") == 0) {
        return handleADRP(insn, insnDesc, insnComment, fatal);
    }
    if (strcmp(mnemonic, "ldr") == 0) {
        return handleLDR(insn, insnDesc, insnComment, false, fatal);
    }
    if (strcmp(mnemonic, "ldrsw") == 0) {
        return handleLDR(insn, insnDesc, insnComment, true, fatal);
    }
    if (strcmp(mnemonic, "adr") == 0) {
        return handleADR(insn, insnDesc, insnComment, fatal);
    }
    if (strcmp(mnemonic, "mov") == 0) {
        return handleMOV(insn, insnDesc, insnComment, fatal);
    }
    return true;
}


bool ARM64Runtime::handleSTP(cs_insn *insn, string *insnDesc, string *insnComment, bool fatal) {
    uint8_t opcount = insn[0].detail->arm64.op_count;
    struct cs_arm64 detail = insn[0].detail->arm64;
    string analyzeDesc = "";
    
    VirtualMemory *vm = VirtualMemory::progressDefault();
    ARM64ThreadState *state = ARM64ThreadState::mainThreadState();
    uint64_t sp = state->sp->getValue();

    ASMAssert(opcount >= 3, fatal);
    
    // STP  Xt1, Xt2, expr
    struct cs_arm64_op ra = detail.operands[0];
    struct cs_arm64_op rb = detail.operands[1];
    
    ARM64Register *xa = state->getRegisterFromOprand(ra);
    ARM64Register *xb = state->getRegisterFromOprand(rb);
    ASMAssert(xa && xb, fatal);
    ASMAssert(xa->available && xb->available, fatal);
    
    // STP  Xt1, Xt2, [Xn|SP], #imm ; Post-index, store->offset->writeback
    // STP <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]! ; Pre-index, offset->store->writeback
    // Signed offset ???
    bool writeback = detail.writeback;
    if (opcount == 3) {
        // pre-index
        cs_arm64_op opmem = detail.operands[2];
        ASMAssert(opmem.type == ARM64_OP_MEM, fatal);
        
        arm64_reg regType = opmem.mem.base;
        int32_t disp = opmem.mem.disp;
        if (regType == ARM64_REG_SP) {
            uint64_t addr;
            if (writeback) {
                sp = sp + disp;
                addr = sp;
                analyzeDesc = StringUtils::format(" ; sub sp to 0x%llx", sp);
                state->sp->setValue(&sp, 8);
            } else {
                addr = sp + disp;
                analyzeDesc = StringUtils::format(" ; get addr by sp 0x%llx", sp);
            }
            
            // store 64bits
            vm->storeRegister(xa, addr);
            analyzeDesc += StringUtils::format(", store %s(available=%d, value=%s) to 0x%llx", xa->getDesc().c_str(), xa->available, xa->getValueDesc().c_str(), addr);
            
            addr += 8;
            vm->storeRegister(xb, addr);
            analyzeDesc += StringUtils::format(", store %s(available=%d, value=%s) to 0x%llx", xb->getDesc().c_str(), xb->available, xb->getValueDesc().c_str(), addr);
        }
    }
    
    if (insnComment && analyzeDesc.length() > 0) {
        *insnComment = analyzeDesc;
    }
    return true;
}

bool ARM64Runtime::handleSTR(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal) {
    uint8_t opcount = insn[0].detail->arm64.op_count;
    struct cs_arm64 detail = insn[0].detail->arm64;
    string analyzeDesc = "";
    
    VirtualMemory *vm = VirtualMemory::progressDefault();
    ARM64ThreadState *state = ARM64ThreadState::mainThreadState();
    ASMAssert(opcount >= 2, fatal);
    
    /**
     STR (immediate) 3 classes: post-index, pre-index, unsigned-offset
        imm9: signed, -256 ~ 255
        imm12: unsigned, 0 ~ 4096
            32bit: multiply by 4, that is 0 ~ 16384
            64bit: multiply by 8, that is 0 ~ 32768
     
        1. post-index:
                STR <Wt/Xt>, [<Xn|SP>], #<signed-imm9> (write-back)
        2. pre-index:
                STR <Wt/Xt>, [<Xn|SP>], #<signed-imm9>]! (write-back)
                ST(U)R <Wt/Xt>, [<Xn|SP>], #<signed-imm9>]  (not write-back)
        3. unsigned-offset:
                STR <Wt/Xt>, [<Xn|SP>{, #<imm12>}]
     */
    if (opcount == 3) {
        // post-index
        // STR <regFrom>, [<regBase>], #<offset> (write-back)
        // src
        ARM64Register *regFrom = state->getRegisterFromRegType(detail.operands[0].reg);
        ASMAssert(regFrom && regFrom->available, fatal);
        
        // mem
        arm64_op_mem &mem = detail.operands[1].mem;
        ARM64Register *regBase = state->getRegisterFromRegType(mem.base);
        ASMAssert(regBase && regBase->available, fatal);
        
        // offset
        int64_t offset = detail.operands[2].imm;
        
        // store reg and add offset
        vm->storeRegister(regFrom, regBase->getValue());
        
        // writeback
        regBase->setValue(new uint64_t(regBase->getValue() + offset), 8);
    } else if (opcount == 2) {
        // pre-index
        // STR <Wt/Xt>, [<Xn|SP>], #<signed-imm9>]! (write-back)
        // ST(U)R <Wt/Xt>, [<Xn|SP>], #<signed-imm9>]  (not write-back)
        
        // src
        ARM64Register *regFrom = state->getRegisterFromRegType(detail.operands[0].reg);
        ASMAssert(regFrom && regFrom->available, fatal);
        
        // mem
        arm64_op_mem mem = detail.operands[1].mem;
        ARM64Register *regBase = state->getRegisterFromRegType(mem.base);
        ASMAssert(regBase && regBase->available, fatal);
        int32_t offset = mem.disp;
        uint64_t address = regBase->getValue() + offset;
        
        // store reg
        vm->storeRegister(regFrom, address);
        
        // write back if needed
        if (detail.writeback) {
            regBase->setValue(new uint64_t(address), 8);
        }
    }
    
    if (insnComment && analyzeDesc.length() > 0) {
        *insnComment = analyzeDesc;
    }
    return true;
}

bool ARM64Runtime::handleADD(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal) {
    // ADD <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}
    struct cs_arm64 detail = insn[0].detail->arm64;
    string analyzeDesc = "";
    
    ARM64ThreadState *state = ARM64ThreadState::mainThreadState();
    
    // ADD <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}
    ARM64Register *dst = state->getRegisterFromOprand(detail.operands[0]);
    ASMAssert(dst != nullptr, fatal);
    
    uint64_t result = 0;
    bool avaliable = true;
    
    string xaDesc;
    if (detail.operands[1].type == ARM64_OP_IMM) {
        result += detail.operands[1].imm;
        xaDesc = StringUtils::format("#%lld", detail.operands[1].imm);
    } else {
        ARM64Register *xa = state->getRegisterFromOprand(detail.operands[1]);
        if (xa->available) {
            result += xa->getValue();
        } else {
            avaliable = false;
        }
        xaDesc = xa->getDesc();
    }
    
    string xbDesc;
    if (detail.operands[2].type == ARM64_OP_IMM) {
        result += detail.operands[2].imm;
        xbDesc = StringUtils::format("#%lld", detail.operands[2].imm);
    } else {
        ARM64Register *xb = state->getRegisterFromOprand(detail.operands[2]);
        if (xb) {
            if (xb->available) {
                result += xb->getValue();
            } else {
                avaliable = false;
            }
        }
        xbDesc = xb->getDesc();
    }
    
    // store to dst
    dst->setValue(&result, 8);
    analyzeDesc = StringUtils::format(" ; %s = %s + %s = 0x%llx, available = %d", dst->getDesc().c_str(), xaDesc.c_str(), xbDesc.c_str(), result, avaliable);
    if (insnComment) {
        *insnComment = analyzeDesc;
    }
    return true;
}

bool ARM64Runtime::handleADRP(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal) {
    // ADRP <Xd>, <label>
    struct cs_arm64 detail = insn[0].detail->arm64;
    string analyzeDesc = "";
    
    ARM64ThreadState *state = ARM64ThreadState::mainThreadState();
    
    ARM64Register *dst = state->getRegisterFromOprand(detail.operands[0]);
    ASMAssert(dst, fatal);
    uint64_t addr = detail.operands[1].imm;
    dst->setValue(&addr, 8);
    analyzeDesc = StringUtils::format(" ; %s = %s, available = %d", dst->getDesc().c_str(), dst->getValueDesc().c_str(), dst->available);
    if (insnComment) {
        *insnComment = analyzeDesc;
    }
    return true;
}

bool ARM64Runtime::handleLDR(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool swMode, bool fatal) {
    struct cs_arm64 detail = insn[0].detail->arm64;
    string analyzeDesc = "";
    uint8_t opcount = detail.op_count;
    
    VirtualMemory *vm = VirtualMemory::progressDefault();
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    ARM64ThreadState *state = ARM64ThreadState::mainThreadState();
    
    ARM64Register *dst = state->getRegisterFromOprand(detail.operands[0]);
    ASMAssert(dst != nullptr, fatal);
    
    uint64_t addr = 0;
    bool available = true;
    // LDR <Dt>, [<Xn|SP>], #<simm> ; post-index
    if (opcount == 3) {
        // TODO: not impl
        if (fatal) {
            assert(false);
        }
        return false;
    }
    
    // FIXME: writeback
    // LDR <Dt>, [<Xn|SP>, #<simm>] ; pre-index
    if (opcount == 2) {
        // LDR <dst>, #imm
        if (detail.operands[1].type == ARM64_OP_IMM) {
            addr = detail.operands[1].imm;
        } else {
            // LDR <dst>, [<base>, <index>/#disp]
            if (detail.operands[1].mem.index == ARM64_REG_INVALID) {
                addr = detail.operands[1].mem.disp;
            } else {
                ARM64Register *index = state->getRegisterFromRegType(detail.operands[1].mem.index);
                ASMAssert(index && index->available, fatal);
                addr = index->getValue();
            }
            
            ARM64Register *baseX = state->getRegisterFromRegType(detail.operands[1].mem.base);
            available = baseX->available;
            if (available) {
                addr += baseX->getValue();
            }
        }
    }
    
    // parse error or externel ptr (dyld linker)
    if (!vm->isValidAddress(addr)) {
        if (fatal) {
            assert(false);
        }
        available = false;
    }
    
    // load uint64 data
    uint64_t readSize = swMode ? 4 : 8;
    if (available) {
        void *valuePtr = (void *)vm2->readBySize(addr, readSize);
        if (valuePtr != nullptr) {
            dst->setValue(valuePtr, readSize);
        } else {
            dst->available = false;
        }
    } else {
        dst->available = false;
    }
    
    if (dst->available) {
        analyzeDesc = StringUtils::format(" ; %s = %s, available = %d", dst->getDesc().c_str(), dst->getValueDesc().c_str(), dst->available);
    } else {
        analyzeDesc = StringUtils::format(" ; cannot read from 0x%llx, available = false", addr);
    }
    
    if (insnComment) {
        *insnComment = analyzeDesc;
    }
    return true;
}

bool ARM64Runtime::handleADR(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal) {
    struct cs_arm64 detail = insn[0].detail->arm64;
    string analyzeDesc = "";
    uint8_t opcount = detail.op_count;
    
    ARM64ThreadState *state = ARM64ThreadState::mainThreadState();
    ARM64Register *dst = state->getRegisterFromOprand(detail.operands[0]);
    uint64_t addr = 0;
    ASMAssert(opcount == 2, fatal);
    
    // ADR <Xd>, <label>
    addr = detail.operands[1].imm;
    dst->setValue(&addr, 8);
    
    analyzeDesc = StringUtils::format(" ; %s = %s, available = %d", dst->getDesc().c_str(), dst->getValueDesc().c_str(), dst->available);
    
    if (insnComment) {
        *insnComment = analyzeDesc;
    }
    return true;
}

bool ARM64Runtime::handleMOV(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal) {
    // MOV <Xd>, <Xm>
    struct cs_arm64 detail = insn[0].detail->arm64;
    string analyzeDesc = "";
    
    ARM64ThreadState *state = ARM64ThreadState::mainThreadState();
    
    ARM64Register *dst = state->getRegisterFromOprand(detail.operands[0]);
    ARM64Register *src = state->getRegisterFromOprand(detail.operands[1]);
    ASMAssert(dst && src, fatal);
    ASMAssert(src->available, fatal);
    dst->movFrom(src);
    analyzeDesc = StringUtils::format(" ; %s = %s = %s, available = %d", dst->getDesc().c_str(), src->getDesc().c_str(), src->getValueDesc().c_str(), src->available);
    
    if (insnComment) {
        *insnComment = analyzeDesc;
    }
    return true;
}

bool ARM64Runtime::isRET(cs_insn *insn) {
    const char *mnemonic = insn[0].mnemonic;
    if (strcmp(mnemonic, "ret") == 0) {
        return true;
    }
    if (strcmp(insn[0].mnemonic, "b") == 0 ||
        strncmp(insn[0].mnemonic, "b.", 2) == 0) {
        uint64_t pc = insn[0].detail->arm64.operands[0].imm;
        SymbolTable *symtab = SymbolTable::getInstance();
        Symbol *symbol = symtab->getSymbolByAddress(pc);
        if (symbol == nullptr) {
            return false;
        }
        const char *fname = symbol->name.c_str();
        if (strcmp(fname, "_objc_retainAutoreleaseReturnValue") == 0 ||
            strcmp(fname, "_objc_retainAutoreleasedReturnValue") == 0 ||
            strcmp(fname, "_objc_autoreleaseReturnValue") == 0 ||
            strcmp(fname, "_objc_unsafeClaimAutoreleasedReturnValue") == 0 ||
            strcmp(fname, "_objc_retain") == 0 ||
            strcmp(fname, "_objc_storeWeak") == 0 ||
            strcmp(fname, "_objc_storeStrong") == 0 ||
            strcmp(fname, "_objc_loadWeakRetained") == 0 ||
            strcmp(fname, "_objc_release") == 0 ||
            strcmp(fname, "_objc_destroyWeak") == 0 ||
            strcmp(fname, "_objc_copyWeak") == 0) {
            return true;
        }
    }
    if (strcmp(insn[0].mnemonic, "bl") == 0) {
        uint64_t pc = insn[0].detail->arm64.operands[0].imm;
        SymbolTable *symtab = SymbolTable::getInstance();
        Symbol *symbol = symtab->getSymbolByAddress(pc);
        if (symbol == nullptr) {
            return false;
        }
        const char *fname = symbol->name.c_str();
        if (strcmp(fname, "___stack_chk_fail") == 0) {
            return true;
        }
    }
    return false;
}
