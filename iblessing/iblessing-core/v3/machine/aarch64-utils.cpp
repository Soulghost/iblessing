//
//  aarch64-utils.cpp
//  aarch64-utils
//
//  Created by Soulghost on 2021/12/5.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-utils.hpp"

using namespace std;

uint64_t callFunctionLR = 0x1fee11337aaa;

uint64_t uc_callFunction(uc_engine *uc, uint64_t function, Aarch64FunctionCallArg returnValue, vector<Aarch64FunctionCallArg> args) {
    ensure_uc_reg_write(UC_ARM64_REG_LR, &callFunctionLR);
    for (size_t i = 0; i < args.size(); i++) {
        Aarch64FunctionCallArg &arg = args[i];
        uc_arm64_reg reg;
        switch (arg.type) {
            case Aarch64FunctionCallArgTypeInt64: {
                reg = (uc_arm64_reg)((int)UC_ARM64_REG_X0 + i);
                ensure_uc_reg_write(reg, arg.data);
                break;
            }
            case Aarch64FunctionCallArgTypeInt32: {
                reg = (uc_arm64_reg)((int)UC_ARM64_REG_W0 + i);
                ensure_uc_reg_write(reg, arg.data);
                break;
            }
            default:
                assert(false);
                break;
        }
    }
    uc_err err = uc_emu_start(uc, function, callFunctionLR, 0, 0);
    assert(err == UC_ERR_OK);
    
    switch (returnValue.type) {
        case Aarch64FunctionCallArgTypeVoid: {
            return 0;
        }
        case Aarch64FunctionCallArgTypeInt64: {
            uint64_t x0;
            ensure_uc_reg_read(UC_ARM64_REG_X0, &x0);
            return x0;
        }
        case Aarch64FunctionCallArgTypeInt32: {
            uint32_t w0;
            ensure_uc_reg_read(UC_ARM64_REG_W0, &w0);
            return w0;
        }
        default:
            assert(false);
    }
    return 0;
}
