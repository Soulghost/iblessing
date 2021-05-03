//
//  AntiWrapper.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "AntiWrapper.hpp"
#include <iblessing-core/v2/util/StringUtils.h>

using namespace std;
using namespace iblessing;

string AntiWrapperRegLink::getIDAExpr() {
    if (current >= ARM64_REG_X0 && current <= ARM64_REG_X28) {
        return StringUtils::format("x%d", current - ARM64_REG_X0);
    }
    if (current >= ARM64_REG_X29 && current <= ARM64_REG_X30) {
        return StringUtils::format("x%d", 29 + current - ARM64_REG_X29);
    }
    assert(false);
    return "";
}

AntiWrapperRegLink AntiWrapperRegLink::getRootSource() {
    AntiWrapperRegLink *cur = this;
    while (cur && cur->from != nullptr && cur->from != this) {
        cur = cur->from;
    }
    return *cur;
}

AntiWrapperRegLink* AntiWrapperRegLinkGraph::linkFromOp(cs_arm64_op op) {
    AntiWrapperRegLink *link = nullptr;
    if (op.reg >= ARM64_REG_X0 && op.reg <= ARM64_REG_X28) {
        link = x[op.reg - ARM64_REG_X0];
        link->current = op.reg;
    }
    if (op.reg >= ARM64_REG_X29 && op.reg <= ARM64_REG_X30) {
        link = x[29 + op.reg - ARM64_REG_X29];
        link->current = op.reg;
    }
    return link;
}

bool AntiWrapperRegLinkGraph::createLink(cs_arm64_op src, cs_arm64_op dst) {
    AntiWrapperRegLink *srcLink = linkFromOp(src);
    AntiWrapperRegLink *dstLink = linkFromOp(dst);
    if (!srcLink || !dstLink) {
        return false;
    }
    
    srcLink->active = true;
    dstLink->active = true;
    srcLink->from = dstLink;
    return true;
}

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


