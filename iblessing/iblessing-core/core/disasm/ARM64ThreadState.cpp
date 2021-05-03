//
//  ARM64ThreadState.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ARM64ThreadState.hpp"
#include "VirtualMemory.hpp"

using namespace std;
using namespace iblessing;

ARM64ThreadState* ARM64ThreadState::_instance = nullptr;

ARM64ThreadState* ARM64ThreadState::mainThreadState() {
    if (ARM64ThreadState::_instance == nullptr) {
        ARM64ThreadState::_instance = new ARM64ThreadState();
    }
    return ARM64ThreadState::_instance;
}

ARM64ThreadState::ARM64ThreadState() {
    // init x registers
    x.clear();
    for (int i = 0; i < 31; i++) {
        ARM64RegisterX *rx = new ARM64RegisterX(i);
        x.push_back(rx);
    }
    
    // init sp
    sp = new ARM64RegisterSP(VirtualMemory::progressDefault()->spUpperBound);
    
    // init d
    d.clear();
    for (int i = 0; i < 32; i++) {
        ARM64RegisterD *rd = new ARM64RegisterD(i);
        d.push_back(rd);
    }
}

ARM64Register* ARM64ThreadState::getRegisterFromOprand(cs_arm64_op op) {
    assert(op.type == ARM64_OP_REG);
    return getRegisterFromRegType(op.reg);
}

ARM64Register* ARM64ThreadState::getRegisterFromRegType(arm64_reg reg) {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        return x[reg - ARM64_REG_X0]->setX();
    }
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
        return x[reg - ARM64_REG_W0]->setW();
    }
    if (reg == ARM64_REG_X29) {
        return x[29]->setX();
    }
    if (reg == ARM64_REG_X30) {
        return x[30]->setX();
    }
    if (reg == ARM64_REG_SP) {
        return sp;
    }
    
    // SMID
    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        return d[reg - ARM64_REG_D0];
    }
    return nullptr;
}
