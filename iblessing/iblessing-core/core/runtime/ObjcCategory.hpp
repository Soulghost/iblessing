//
//  ObjcCategory.hpp
//  iblessing
//
//  Created by soulghost on 2020/10/3.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcCategory_hpp
#define ObjcCategory_hpp

#include <iblessing-core/core/runtime/ObjcClass.hpp>

NS_IB_BEGIN

class ObjcRuntime;
class SymbolTable;

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
    
    static std::shared_ptr<ObjcCategory> loadFromAddress(std::shared_ptr<SymbolTable> symtab, ObjcRuntime *runtime, std::shared_ptr<VirtualMemoryV2> vm2, uint64_t address);
};

NS_IB_END

#endif /* ObjcCategory_hpp */
