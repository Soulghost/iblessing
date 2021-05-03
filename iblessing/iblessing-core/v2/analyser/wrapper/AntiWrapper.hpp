//
//  AntiWrapper.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef AntiWrapper_hpp
#define AntiWrapper_hpp

#include <iblessing-core/infra/Object.hpp>
#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <map>
#include <vector>
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
    
    AntiWrapperRegLink(const AntiWrapperRegLink &f) {
        active = f.active;
        current = f.current;
        from = f.from;
    }
    
    AntiWrapperRegLink getRootSource();
    std::string getIDAExpr();
};

struct AntiWrapperRegLinkGraph {
    std::vector<AntiWrapperRegLink *> x{31, nullptr};
    
    AntiWrapperRegLinkGraph() {
        for (int i = 0; i <= 28; i++) {
            this->x[i] = new AntiWrapperRegLink();
            this->x[i]->current = static_cast<arm64_reg>((int)ARM64_REG_X0 + i);
        }
        for (int i = 29; i <= 30; i++) {
            this->x[i] = new AntiWrapperRegLink();
            this->x[i]->current = static_cast<arm64_reg>((int)ARM64_REG_X29 + i - 29);
        }
    }
    
    ~AntiWrapperRegLinkGraph() {

    }
    
    AntiWrapperRegLink* linkFromOp(cs_arm64_op op);
    bool createLink(cs_arm64_op src, cs_arm64_op dst);
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
