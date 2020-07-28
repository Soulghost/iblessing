//
//  FunctionPrototype.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef FunctionPrototype_hpp
#define FunctionPrototype_hpp

#include "Object.hpp"
#include <vector>

NS_IB_BEGIN

struct FunctionProtoType {
    int nArgs;
    bool variadic;
    std::string returnType;
    std::vector<std::string> argTypes;
};

NS_IB_END

#endif /* FunctionPrototype_hpp */
