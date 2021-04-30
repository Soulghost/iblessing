//
//  ObjcCategory.hpp
//  iblessing
//
//  Created by soulghost on 2020/10/3.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcCategory_hpp
#define ObjcCategory_hpp

#include "Object.hpp"
#include "ObjcClass.hpp"
#include <vector>
#include "VirtualMemoryV2.hpp"

NS_IB_BEGIN

class ObjcRuntime;

class ObjcCategoryDecoratedClass {
public:
    bool isExternal;
    uint64_t address;
    ObjcClassRuntimeInfo *classInfo;
};

class ObjcCategory {
public:
    std::string name;
    std::shared_ptr<ObjcCategoryDecoratedClass> decoratedClass;
    std::vector<std::shared_ptr<ObjcMethod>> instanceMethods;
    std::vector<std::shared_ptr<ObjcMethod>> classMethods;
    
    static std::shared_ptr<ObjcCategory> loadFromAddress(uint64_t address);
    static std::shared_ptr<ObjcCategory> loadFromAddress(ObjcRuntime *runtime, std::shared_ptr<VirtualMemoryV2> vm2, uint64_t address);
};

NS_IB_END

#endif /* ObjcCategory_hpp */
