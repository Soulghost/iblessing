//
//  AntiWrapper.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "AntiWrapper.hpp"

using namespace std;
using namespace iblessing;

void AntiWrapper::setSimpleWrapper(AntiWrapperBlock block) {
    simpleWrapperMap[block.startAddr] = block;
}

bool AntiWrapper::isWrappedCall(uint64_t addr) {
    return simpleWrapperMap.find(addr) != simpleWrapperMap.end();
}

AntiWrapperArgs AntiWrapper::performWrapperTransform(uint64_t addr, AntiWrapperArgs args) {
    AntiWrapperBlock &block = simpleWrapperMap[addr];
    return block.transformer(block, args);
}
