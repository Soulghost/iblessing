//
//  aarch64-utils.hpp
//  aarch64-utils
//
//  Created by Soulghost on 2021/12/5.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef aarch64_utils_hpp
#define aarch64_utils_hpp

#include <vector>
#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>

extern uint64_t callFunctionLR;
extern uint64_t redirectFunctionLR;

enum Aarch64FunctionCallArgType {
    Aarch64FunctionCallArgTypeVoid = 0,
    Aarch64FunctionCallArgTypeInt64,
    Aarch64FunctionCallArgTypeInt32,
    Aarch64FunctionCallArgTypeCString
};

typedef struct Aarch64FunctionCallArg {
    Aarch64FunctionCallArgType type;
    void *data;
    std::vector<uint64_t> freelist;
    
    Aarch64FunctionCallArg() {
        type = Aarch64FunctionCallArgTypeVoid;
        data = NULL;
    }
    
    ~Aarch64FunctionCallArg() {
//        for (uint64_t addr : freelist) {
//            free((void *)addr);
//        }
//        freelist.clear();
    }
    
    Aarch64FunctionCallArg(uint64_t val) {
        type = Aarch64FunctionCallArgTypeInt64;
        uint64_t *buf = (uint64_t *)malloc(sizeof(uint64_t));
        *buf = val;
        data = buf;
        freelist.push_back((uint64_t)buf);
    }
    
    static Aarch64FunctionCallArg voidArg() {
        Aarch64FunctionCallArg arg;
        return arg;
    }
} Aarch64FunctionCallArg;

extern uint64_t uc_callFunction(uc_engine *uc, uint64_t function, Aarch64FunctionCallArg returnValue, std::vector<Aarch64FunctionCallArg> args);
extern uint64_t uc_redirectToFunction(uc_engine *uc, uint64_t function, Aarch64FunctionCallArg returnValue, std::vector<Aarch64FunctionCallArg> args);

#endif /* aarch64_utils_hpp */
