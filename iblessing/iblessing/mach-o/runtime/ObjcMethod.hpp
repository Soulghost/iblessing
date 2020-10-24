//
//  ObjcMethod.hpp
//  iblessing
//
//  Created by soulghost on 2020/3/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcMethod_hpp
#define ObjcMethod_hpp

#include "Object.hpp"
#include "Vector.hpp"
#include <unordered_map>

NS_IB_BEGIN

class ObjcClassRuntimeInfo;

class ObjcMethod : public Object {
public:
    bool isClassMethod;
    bool isDummy;
    std::string name;
    std::string types;
    std::vector<std::string> argTypes;
    uint64_t imp;
    ObjcClassRuntimeInfo *classInfo;
    
    ObjcMethod(): isDummy(false) {}
    static ObjcMethod* createDummy(std::string name);
    bool operator < (ObjcMethod *other) {
        return name < other->name;
    }
    
    std::string desc();
};

NS_IB_END

#endif /* ObjcMethod_hpp */
