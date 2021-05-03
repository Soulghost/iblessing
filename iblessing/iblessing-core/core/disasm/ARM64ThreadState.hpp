//
//  ARM64ThreadState.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ARM64ThreadState_hpp
#define ARM64ThreadState_hpp

#include <iblessing-core/infra/Object.hpp>
#include "ARM64Registers.hpp"
#include <vector>
#include <iblessing-core/v2/vendor/capstone/capstone.h>

NS_IB_BEGIN

class ARM64ThreadState {
public:
    static ARM64ThreadState* mainThreadState();
    
    ARM64RegisterSP *sp;
    std::vector<ARM64RegisterX *> x;
    // SMID - Single Instruction Multiple Data
    std::vector<ARM64RegisterD *> d;
    ARM64Register* getRegisterFromOprand(cs_arm64_op op);
    ARM64Register* getRegisterFromRegType(arm64_reg reg);
    
protected:
    ARM64ThreadState();
    
private:
    static ARM64ThreadState *_instance;
};

NS_IB_END

#endif /* ARM64ThreadState_hpp */
