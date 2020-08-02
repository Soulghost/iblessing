//
//  ObjcMethodChain.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcMethodChain_hpp
#define ObjcMethodChain_hpp

#include "Object.hpp"
#include <unistd.h>
#include <set>
#include <string>
#include "StringUtils.h"

NS_IB_BEGIN

class MethodChain {
public:
    static uint64_t chainIdCounter;
    uint64_t chainId;
    uint64_t impAddr;
    std::string prefix;
    std::string className;
    std::string methodName;
    
    std::set<std::pair<MethodChain *, uint64_t>> prevMethods;
    std::set<std::pair<MethodChain *, uint64_t>> nextMethods;
    
    MethodChain() {
        chainId = ++chainIdCounter;
    }
    
    std::string getCommonDesc() {
        return StringUtils::format("%s[%s %s] (0x%llx)",
                                   prefix.c_str(),
                                   className.c_str(),
                                   methodName.c_str(),
                                   impAddr);
    }
    
    std::string getCompareKey() {
        if (className.rfind("0x") == 0) {
            return StringUtils::format("%s[%s %s]",
                                       prefix.c_str(),
                                       "0xcafecafecafecafe",
                                       methodName.c_str());
        } else {
            return StringUtils::format("%s[%s %s]",
                                       prefix.c_str(),
                                       className.c_str(),
                                       methodName.c_str());
        }
    }
    
    bool operator < (MethodChain *rhs) {
        return getCommonDesc() < rhs->getCommonDesc();
    }
};

NS_IB_END

#endif /* ObjcMethodChain_hpp */
