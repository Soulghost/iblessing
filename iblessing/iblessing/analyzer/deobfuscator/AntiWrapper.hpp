//
//  AntiWrapper.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef AntiWrapper_hpp
#define AntiWrapper_hpp

#include "Object.hpp"
#include <map>

NS_IB_BEGIN;

struct AntiWrapperBlock;

struct AntiWrapperArgs {
    uint64_t x[31];
    uint8_t nArgs;
};

typedef std::function<AntiWrapperArgs (AntiWrapperBlock block, AntiWrapperArgs args)> AntiWrapperTransformer;

struct AntiWrapperBlock {
    uint64_t startAddr;
    uint64_t endAddr;
    std::string symbolName;
    AntiWrapperTransformer transformer;
};

class AntiWrapper {
public:
    std::map<uint64_t, AntiWrapperBlock> simpleWrapperMap;
    
    void setSimpleWrapper(AntiWrapperBlock block);
    bool isWrappedCall(uint64_t addr);
    AntiWrapperArgs performWrapperTransform(uint64_t addr, AntiWrapperArgs args);
};

NS_IB_END;

#endif /* AntiWrapper_hpp */
