//
//  ObjcBlock.hpp
//  iblessing
//
//  Created by soulghost on 2020/8/5.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcBlock_hpp
#define ObjcBlock_hpp

#include "Object.hpp"

NS_IB_BEGIN

class ObjcBlock : public Object {
public:
    void *stack;
    uint64_t stackSize;
    uint64_t invoker;
};

NS_IB_END

#endif /* ObjcBlock_hpp */
