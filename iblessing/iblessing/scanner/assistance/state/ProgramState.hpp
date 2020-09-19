//
//  ProgramState.hpp
//  iblessing
//
//  Created by soulghost on 2020/9/18.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ProgramState_hpp
#define ProgramState_hpp

#include "Object.hpp"
#include <unicorn/unicorn.h>

NS_IB_BEGIN

class ProgramState {
public:
    uc_context *uc_ctx;
    uint64_t pc;
    uint32_t depth;
    std::string condition;
};

NS_IB_END

#endif /* ProgramState_hpp */
