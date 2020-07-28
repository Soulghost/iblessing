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
#include <capstone/capstone.h>
#include "StringUtils.h"
#include <map>
#include <cassert>

NS_IB_BEGIN;

struct AntiWrapperBlock;

struct AntiWrapperArgs {
    uint64_t x[31];
    uint8_t nArgs;
};

struct AntiWrapperRegLink {
    bool active;
    arm64_reg current;
    AntiWrapperRegLink *from;
    
    AntiWrapperRegLink() {
        active = false;
        current = ARM64_REG_INVALID;
        from = nullptr;
    }
    
    AntiWrapperRegLink getRootSource() {
        AntiWrapperRegLink *cur = this;
        while (cur && cur->from != nullptr && cur->from != this) {
            cur = cur->from;
        }
        return *cur;
    }
    
    std::string getIDAExpr() {
        if (current >= ARM64_REG_X0 && current <= ARM64_REG_X28) {
            return StringUtils::format("x%d", current - ARM64_REG_X0);
        }
        if (current >= ARM64_REG_X29 && current <= ARM64_REG_X30) {
            return StringUtils::format("x%d", 29 + current - ARM64_REG_X29);
        }
        assert(false);
        return "";
    }
};

struct AntiWrapperRegLinkGraph {
    AntiWrapperRegLink x[31];
    
    AntiWrapperRegLinkGraph() {
        for (int i = 0; i <= 28; i++) {
            this->x[i].current = static_cast<arm64_reg>((int)ARM64_REG_X0 + i);
        }
        for (int i = 29; i <= 30; i++) {
            this->x[i].current = static_cast<arm64_reg>((int)ARM64_REG_X29 + i - 29);
        }
    }
    
    AntiWrapperRegLink* linkFromOp(cs_arm64_op op) {
        AntiWrapperRegLink *link = nullptr;
        if (op.reg >= ARM64_REG_X0 && op.reg <= ARM64_REG_X28) {
            link = &x[op.reg - ARM64_REG_X0];
            link->current = op.reg;
        }
        if (op.reg >= ARM64_REG_X29 && op.reg <= ARM64_REG_X30) {
            link = &x[29 + op.reg - ARM64_REG_X29];
            link->current = op.reg;
        }
        return link;
    }
    
    bool createLink(cs_arm64_op src, cs_arm64_op dst) {
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
};

typedef std::function<AntiWrapperArgs (AntiWrapperBlock block, AntiWrapperArgs args)> AntiWrapperTransformer;

struct AntiWrapperBlock {
    uint64_t startAddr;
    uint64_t endAddr;
    std::string symbolName;
    AntiWrapperTransformer transformer;
    AntiWrapperRegLinkGraph regLinkGraph;
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
