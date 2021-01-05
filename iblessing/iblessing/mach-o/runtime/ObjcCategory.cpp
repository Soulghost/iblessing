//
//  ObjcCategory.cpp
//  iblessing
//
//  Created by soulghost on 2020/10/3.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcCategory.hpp"
#include "VirtualMemoryV2.hpp"
#include "ObjcRuntime.hpp"
#include "SymbolTable.hpp"
#include "StringUtils.h"
#include "CoreFoundation.hpp"

using namespace std;
using namespace iblessing;

/**
00000000 __objc2_category struc ; (sizeof=0x30, align=0x8, copyof_45)
00000000                                         ; XREF: __objc_const:_OBJC_CATEGORY_NSString_$_IBS/r
00000000 name            DCQ ?                   ; offset
00000008 _class          DCQ ?                   ; offset
00000010 inst_meths      DCQ ?                   ; offset
00000018 class_meths     DCQ ?                   ; offset
00000020 prots           DCQ ?                   ; offset
00000028 props           DCQ ?                   ; offset
00000030 __objc2_category ends
*/

static vector<shared_ptr<ObjcMethod>> loadMethodsFromAddress(uint64_t address, ObjcClassRuntimeInfo *classInfo, bool classMethod) {
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    uint32_t count = vm2->read32(address + 4, nullptr);
    if (count == 0) {
        return {};
    }
    
    vector<shared_ptr<ObjcMethod>> methods;
    SymbolTable *symtab = SymbolTable::getInstance();
    uint64_t objc_classmethods_addr = address + 8;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t sel_offset = objc_classmethods_addr;
        uint64_t sel_addr = vm2->read64(sel_offset, nullptr);
        char *sel_ptr = vm2->readString(sel_addr, 1000);
        if (!sel_ptr) {
            objc_classmethods_addr += 24;
            continue;
        }
        std::string sel_str = std::string(sel_ptr);
        
        uint64_t types_offset = sel_offset + 8;
        uint64_t types_addr = vm2->read64(types_offset, nullptr);
        char *types_ptr = vm2->readString(types_addr, 1000);
        if (!types_ptr) {
            objc_classmethods_addr += 24;
            continue;
        }
        std::string types_str = std::string(types_ptr);
        
        uint64_t imp_offset = types_offset + 8;
        uint64_t imp_addr = vm2->read64(imp_offset, nullptr);
        if (!imp_addr) {
            objc_classmethods_addr += 24;
            continue;
        }
        
        // add to class method list
        shared_ptr<ObjcMethod> method = make_shared<ObjcMethod>();
        method->name = sel_str;
        method->types = types_str;
        method->argTypes = CoreFoundation::argumentsFromSignature(types_ptr);
        method->imp = imp_addr;
        method->isClassMethod = classMethod;
        method->classInfo = classInfo;
        methods.push_back(method);
        
        // add to symbol table
        std::string symbolName = StringUtils::format("+[%s %s]", classInfo->className.c_str(), method->name.c_str());
        Symbol *symbol = new Symbol();
        symbol->name = symbolName;
        struct ib_nlist_64 *nl_info = (struct ib_nlist_64 *)malloc(sizeof(struct ib_nlist_64));
        nl_info->n_value = imp_addr;
        symbol->info = nl_info;
        symtab->insertSymbol(symbol);
        
        objc_classmethods_addr += 24;
    }
    
    return methods;
}

shared_ptr<ObjcCategory> ObjcCategory::loadFromAddress(uint64_t address) {
    shared_ptr<ObjcCategory> category = make_shared<ObjcCategory>();
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    uint64_t namePtr = vm2->read64(address, nullptr);
    if (!namePtr) {
        return nullptr;
    }
    string name = vm2->readString(namePtr, 1000);
    category->name = name;
    address += 8;
    
    uint64_t classPtr = vm2->read64(address, nullptr);
    if (!classPtr) {
        return nullptr;
    }
    category->decoratedClass = make_shared<ObjcCategoryDecoratedClass>();
    uint64_t classAddr = vm2->read64(classPtr, nullptr);
    category->decoratedClass->address = classAddr;
    if (classAddr) {
        ObjcClassRuntimeInfo *classInfo = ObjcRuntime::getInstance()->getClassInfoByAddress(classAddr);
        category->decoratedClass->classInfo = classInfo;
    } else {
        category->decoratedClass->classInfo = nullptr;
    }
    address += 8;
    
    uint64_t instanceMethodsAddr = vm2->read64(address, nullptr);
    if (instanceMethodsAddr) {
        category->instanceMethods = loadMethodsFromAddress(instanceMethodsAddr, category->decoratedClass->classInfo, false);
    }
    address += 8;
    
    uint64_t classMethodsAddr = vm2->read64(address, nullptr);
    if (classMethodsAddr) {
        category->classMethods = loadMethodsFromAddress(classMethodsAddr, category->decoratedClass->classInfo, true);
    }
    
    if (category->decoratedClass->classInfo) {
        ObjcClassRuntimeInfo *classInfo = category->decoratedClass->classInfo;
        vector<shared_ptr<ObjcMethod>> allMethods(category->instanceMethods);
        allMethods.insert(allMethods.end(), category->classMethods.begin(), category->classMethods.end());
        for (shared_ptr<ObjcMethod> &method : allMethods) {
            classInfo->methodList.pushBack(method.get());
            classInfo->name2method[method->name] = method.get();
        }
    }
    return category;
}
