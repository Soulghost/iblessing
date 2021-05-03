//
//  ObjcBlock.hpp
//  iblessing
//
//  Created by soulghost on 2020/8/5.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcBlock_hpp
#define ObjcBlock_hpp

#include <iblessing-core/core/runtime/ObjcClass.hpp>

NS_IB_BEGIN

enum BlockVariableType {
    BlockVariableTypePrimary = 0,
    BlockVariableTypeObjcClass,
    BlockVariableTypeUnknown
};

struct BlockVariable {
    BlockVariableType type;
    ObjcClassRuntimeInfo *classInfo;
};

class ObjcBlock : public Object {
public:
    void *stack;
    uint64_t stackSize;
    uint64_t invoker;
    bool commonBlock; // is x0 = self
    std::vector<BlockVariable *> args;
};

NS_IB_END

#endif /* ObjcBlock_hpp */
