//
//  ObjcClass.hpp
//  iblessing
//
//  Created by soulghost on 2020/3/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcClass_hpp
#define ObjcClass_hpp

#include <unordered_map>

#include <iblessing-core/infra/Object.hpp>
#include <iblessing-core/infra/Vector.hpp>
#include <iblessing-core/core/runtime/ObjcMethod.hpp>
#include <iblessing-core/core/runtime/ObjcIvar.hpp>
#include <iblessing-core/core/memory/VirtualMemoryV2.hpp>
#include <iblessing-core/core/symtab/SymbolTable.hpp>

NS_IB_BEGIN

class ObjcRuntime;

class ObjcClassRuntimeInfo {
public:
    ObjcClassRuntimeInfo() {
        isExternal = false;
        isSub = false;
        superClassInfo = nullptr;
    }
    
    bool isExternal;
    bool isSub;
    uint64_t address;
    std::string className;
    Vector<ObjcMethod *> methodList;
    Vector<ObjcIvar *> ivarList;
    ObjcClassRuntimeInfo *superClassInfo;
    std::unordered_map<std::string, ObjcMethod *> name2method;
    std::unordered_map<std::string, ObjcIvar *> name2ivar;
    std::unordered_map<uint64_t, ObjcIvar *> offset2ivar;
    
    static ObjcClassRuntimeInfo* realizeFromAddress(uint64_t address);
    static ObjcClassRuntimeInfo* realizeFromAddress(ObjcRuntime *runtime , std::shared_ptr<SymbolTable> symtab, std::shared_ptr<VirtualMemoryV2> virtualMemory, uint64_t address);
    static std::string classNameAtAddress(uint64_t address);
    static std::string classNameAtAddress(std::shared_ptr<VirtualMemoryV2> virtualMemory, uint64_t address);
    static uint64_t trickAlignForClassRO(uint64_t address);
    ObjcMethod* getMethodBySEL(std::string sel, bool fatal = false);
    Vector<ObjcMethod *> getAllMethods();
    Vector<ObjcIvar *> getAllIvars();
};

NS_IB_END

#endif /* ObjcClass_hpp */
