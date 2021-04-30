//
//  ObjcClass.hpp
//  iblessing
//
//  Created by soulghost on 2020/3/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcClass_hpp
#define ObjcClass_hpp

#include "Object.hpp"
#include "Vector.hpp"
#include <unordered_map>
#include "ObjcMethod.hpp"
#include "ObjcIvar.hpp"
#include "VirtualMemoryV2.hpp"
#include "SymbolTable.hpp"
//#include <iblessing/memory/memory.hpp>

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
