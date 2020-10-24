//
//  ObjcClass.cpp
//  iblessing
//
//  Created by soulghost on 2020/3/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcClass.hpp"
#include "SymbolTable.hpp"
#include "termcolor.h"
#include "StringUtils.h"
#include "ObjcRuntime.hpp"
#include "VirtualMemoryV2.hpp"
#include "CoreFoundation.hpp"
#include <stack>

using namespace std;
using namespace iblessing;

// read file 64 or return nullptr
#define rf64rn(addr) \
vm2->read64(addr, &memOK); \
if (!memOK) { \
    return nullptr; \
}

#define rf32rn(addr) \
vm2->read32(addr, &memOK); \
if (!memOK) { \
    return nullptr; \
}

// read file 64 or continue
#define rf64cnt(addr, expr) \
vm2->read64(addr, &memOK); \
if (!memOK) { \
    expr; \
    continue; \
}

// TODO: add ivar type parsing
// TODO: add ivar call xref

ObjcClassRuntimeInfo* ObjcClassRuntimeInfo::realizeFromAddress(uint64_t address) {
    // FIXME: external class realize
    // FIXME: unsafe when address is invalid
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    ObjcClassRuntimeInfo *info = new ObjcClassRuntimeInfo();
    info->address = address;
    // __DATA,__objc_data
    // get classname from objc_class->ro_data
#if 0
    struct objc_class {
        struct objc_class *isa; // metaclass
        struct objc_class *superclass;
        cache_t cache;
        struct objc_class_rw_t *rw_data; // ???
        struct objc_class_ro_t *ro_data;
    };
    
    struct class_ro_t {
        uint32_t flags;
        uint32_t instanceStart;
        uint32_t instanceSize;
    #ifdef __LP64__
        uint32_t reserved;
    #endif

        const uint8_t * ivarLayout;
        
        const char * name;
        method_list_t * baseMethodList;
        protocol_list_t * baseProtocols;
        const ivar_list_t * ivars;

        const uint8_t * weakIvarLayout;
        property_list_t *baseProperties;

        method_list_t *baseMethods() const {
            return baseMethodList;
        }
    };
#endif
    bool memOK;
    
    uint64_t objc_data_addr = address;
    uint64_t objc_class_ro_offset = objc_data_addr + 32;
    uint64_t objc_class_ro_addr = rf64rn(objc_class_ro_offset);
    objc_class_ro_addr = trickAlignForClassRO(objc_class_ro_addr);
    uint64_t objc_classname_offset = objc_class_ro_addr + 24;
    uint64_t objc_classname_addr = vm2->read64(objc_classname_offset, &memOK);
    if (!memOK) {
        return nullptr;
    }
    
    // ** stringtable is linkedit based
    const char *className = vm2->readString(objc_classname_addr, 1000);
    if (!className) {
        return nullptr;
    }
    info->className = className;
    // get method list from objc_class->rw_data->const->method_list
    uint64_t objc_methodlist_offset = objc_class_ro_addr + 32;
#if 0
    struct entsize_list_tt {
        uint32_t entsizeAndFlags;
        uint32_t count;
        struct method_t first;
    };
    struct method_t {
        SEL name;
        const char *types;
        IMP imp;
    }
#endif
    
    // handle instance methods
    uint64_t objc_methodlist_addr = rf64rn(objc_methodlist_offset);
    uint32_t objc_methodlist_count = objc_methodlist_addr ? vm2->read32(objc_methodlist_addr + 4, &memOK) : 0;
    if (!memOK) {
        return nullptr;
    }
    
    uint64_t objc_methods_addr = objc_methodlist_addr + 8;
    SymbolTable *symtab = SymbolTable::getInstance();
    for (uint32_t i = 0; i < objc_methodlist_count; i++) {
        uint64_t sel_offset = objc_methods_addr;
        uint64_t sel_addr = vm2->read64(sel_offset, &memOK);
        if (!memOK) {
            objc_methods_addr += 24;
            continue;
        }
        
        char *sel_ptr = vm2->readString(sel_addr, 1000);
        if (!sel_ptr) {
            objc_methods_addr += 24;
            continue;
        }
        std::string sel_str = std::string(sel_ptr);
        
        uint64_t types_offset = sel_offset + 8;
        uint64_t types_addr = rf64cnt(types_offset, objc_methods_addr += 24);
        
        char *types_ptr = vm2->readString(types_addr, 1000);
        if (!types_ptr) {
            objc_methods_addr += 24;
            continue;
        }
        
        std::string types_str = std::string(types_ptr);
        
        uint64_t imp_offset = types_offset + 8;
        uint64_t imp_addr = rf64cnt(imp_offset, objc_methods_addr += 24);
        
        ObjcMethod *method = new ObjcMethod();
        method->name = sel_str;
        method->types = types_str;
        method->argTypes = CoreFoundation::argumentsFromSignature(types_ptr);
        method->imp = imp_addr;
        method->isClassMethod = false;
        method->classInfo = info;
        
        info->methodList.pushBack(method);
        info->name2method[sel_str] = method;
        
        // add to symbol table
        std::string symbolName = StringUtils::format("-[%s %s]", info->className.c_str(), method->name.c_str());
        Symbol *symbol = new Symbol();
        symbol->name = symbolName;
        struct ib_nlist_64 *nl_info = (struct ib_nlist_64 *)malloc(sizeof(struct ib_nlist_64));
        nl_info->n_value = imp_addr;
        symbol->info = nl_info;
        symtab->insertSymbol(symbol);
        
        objc_methods_addr += 24;
    }
    
    // handle class methods
    uint64_t objc_metaclass_addr = rf64rn(objc_data_addr);
    uint64_t objc_metaclass_ro_offset = objc_metaclass_addr + 32;
    uint64_t objc_metaclass_ro_addr = rf64rn(objc_metaclass_ro_offset);
    uint64_t objc_classmethodlist_offset = objc_metaclass_ro_addr + 32;
    uint64_t objc_classmethodlist_addr = rf64rn(objc_classmethodlist_offset);
    uint32_t objc_classmethodlist_count = objc_classmethodlist_addr > 0 ? vm2->read32(objc_classmethodlist_addr + 4, &memOK) : 0;
    if (!memOK) {
        return nullptr;
    }
    
    uint64_t objc_classmethods_addr = objc_classmethodlist_addr + 8;
    for (uint32_t i = 0; i < objc_classmethodlist_count; i++) {
        uint64_t sel_offset = objc_classmethods_addr;
        uint64_t sel_addr = rf64cnt(sel_offset, objc_classmethods_addr += 24);
        char *sel_ptr = vm2->readString(sel_addr, 1000);
        if (!sel_ptr) {
            objc_classmethods_addr += 24;
            continue;
        }
        std::string sel_str = std::string(sel_ptr);
        
        uint64_t types_offset = sel_offset + 8;
        uint64_t types_addr = rf64cnt(types_offset, objc_classmethods_addr += 24);
        char *types_ptr = vm2->readString(types_addr, 1000);
        if (!types_ptr) {
            objc_classmethods_addr += 24;
            continue;
        }
        std::string types_str = std::string(types_ptr);
        
        uint64_t imp_offset = types_offset + 8;
        uint64_t imp_addr = rf64cnt(imp_offset, objc_classmethods_addr += 24);
        
        // add to class method list
        ObjcMethod *method = new ObjcMethod();
        method->name = sel_str;
        method->types = types_str;
        method->argTypes = CoreFoundation::argumentsFromSignature(types_ptr);
        method->imp = imp_addr;
        method->isClassMethod = true;
        method->classInfo = info;
        
        info->methodList.pushBack(method);
        info->name2method[sel_str] = method;
        
        // add to symbol table
        std::string symbolName = StringUtils::format("+[%s %s]", info->className.c_str(), method->name.c_str());
        Symbol *symbol = new Symbol();
        symbol->name = symbolName;
        struct ib_nlist_64 *nl_info = (struct ib_nlist_64 *)malloc(sizeof(struct ib_nlist_64));
        nl_info->n_value = imp_addr;
        symbol->info = nl_info;
        symtab->insertSymbol(symbol);
        
        objc_classmethods_addr += 24;
    }
    
    // handle ivars
    uint64_t objc_class_ivars_offset = objc_methodlist_offset + 2 * 8;
    uint64_t objc_class_ivars_addr = rf64rn(objc_class_ivars_offset);
    if (objc_class_ivars_addr != 0) {
        uint32_t objc_class_ivars_count = rf32rn(objc_class_ivars_addr + 4);
        if (objc_class_ivars_count > 0) {
            uint64_t objc_class_ivar_addr = objc_class_ivars_addr + 8;
            while (objc_class_ivars_count--) {
                struct ib_ivar_t *ivar_ptr = (struct ib_ivar_t *)vm2->readBySize(objc_class_ivar_addr, sizeof(struct ib_ivar_t));
                if (!ivar_ptr) {
                    objc_class_ivar_addr += 32;
                    continue;
                }
                
                struct ib_ivar_t ivar = *(struct ib_ivar_t *)ivar_ptr;
                uint64_t nameAddr = (uint64_t)ivar.name;
                uint64_t typeAddr = (uint64_t)ivar.type;
                // fix structure
                ivar.name = vm2->readString(nameAddr, 1000);
                ivar.type = vm2->readString(typeAddr, 1000);
                if (!ivar.name || !ivar.type) {
                    objc_class_ivar_addr += 32;
                    continue;
                }
                
                uint32_t offset = vm2->read32((uint64_t)ivar.offset, &memOK);
                if (!memOK) {
                    objc_class_ivar_addr += 32;
                    continue;
                }
                
                ObjcIvar *objcIvar = new ObjcIvar(ivar);
                objcIvar->clazz = info;
                objcIvar->offset = offset;
                string ivar_type = string(ivar.type);
                
                // objc class type
                if (ivar_type.rfind("@") == 0) {
                    if (ivar_type.length() > 3) {
                        objcIvar->type = IvarTypeObjcClass;
                        objcIvar->typeName = ivar_type.substr(2, ivar_type.length() - 3);
                    } else {
                        objcIvar->type = IvarTypeUnKnown;
                    }
                } else {
                    // FIXME: resolve primary types
                }
                
                string ivarName = ivar.name;
                string getterName;
                if (ivarName.length() > 1) {
                    getterName = ivarName.substr(1);
                } else {
                    getterName = ivarName;
                }
                
                info->ivarList.pushBack(objcIvar);
                info->name2ivar[getterName] = objcIvar;
                info->offset2ivar[offset] = objcIvar;
                objc_class_ivar_addr += 32;
            }
        }
    }
    
    
    // realize superclass
    uint64_t objc_superclass_offset = objc_data_addr + 8;
    uint64_t objc_superclass_addr = rf64rn(objc_superclass_offset);
    if (objc_superclass_addr != 0 && objc_superclass_addr != address) {
        info->superClassInfo = ObjcClassRuntimeInfo::realizeFromAddress(objc_superclass_addr);
    } else {
        info->superClassInfo = nullptr;
    }
    
    ObjcRuntime *rt = ObjcRuntime::getInstance();
    rt->address2RuntimeInfo[address] = info;
    rt->runtimeInfo2address[info] = address;

    return info;
}

Vector<ObjcMethod *> ObjcClassRuntimeInfo::getAllMethods() {
    Vector<ObjcMethod *> methods = methodList;
    ObjcClassRuntimeInfo *info = this->superClassInfo;
    while (info != nullptr) {
        methods.pushBack(info->methodList);
        info = info->superClassInfo;
    }
    return methods;
}

Vector<ObjcIvar *> ObjcClassRuntimeInfo::getAllIvars() {
    stack<ObjcClassRuntimeInfo *> classes;
    ObjcClassRuntimeInfo *info = this;
    while (info != nullptr) {
        classes.push(info);
        info = info->superClassInfo;
    }
    
    Vector<ObjcIvar *> allIvars;
    while (!classes.empty()) {
        ObjcClassRuntimeInfo *info = classes.top();
        classes.pop();
        
        Vector<ObjcIvar *> ivars = info->ivarList;
        Vector<ObjcIvar *> tinyIvars;
        for (auto it = ivars.begin(); it != ivars.end();) {
            if ((*it)->raw.size < 8) {
                // tiny
                tinyIvars.pushBack(*it);
                it = ivars.erase(it);
            } else {
                ++it;
            }
        }
        tinyIvars.pushBack(ivars);
        allIvars.pushBack(tinyIvars);
    }
    return allIvars;
}

ObjcMethod* ObjcClassRuntimeInfo::getMethodBySEL(string sel, bool fatal) {
    ObjcClassRuntimeInfo *info = this;
    while (info != nullptr) {
        if (info->name2method.find(sel) != info->name2method.end()) {
            return info->name2method[sel];
        }
//        for (int i = 0; i < info->methodList.size(); i++) {
//            printf("%s %s\n", info->className.c_str(), info->methodList.at(i)->name.c_str());
//        }
        info = info->superClassInfo;
    }
    if (fatal) {
        assert(false);
    }
    return ObjcMethod::createDummy(sel);
}

std::string ObjcClassRuntimeInfo::classNameAtAddress(uint64_t address) {
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    uint64_t objc_class_ro_offset = address + 32;
    
    bool memOK;
    uint64_t objc_class_ro_addr = vm2->read64(objc_class_ro_offset, &memOK);
    if (!memOK) {
        return "";
    }
    
    objc_class_ro_addr = trickAlignForClassRO(objc_class_ro_addr);
    
    uint64_t objc_classname_offset = objc_class_ro_addr + 24;
    uint64_t objc_classname_addr = vm2->read64(objc_classname_offset, &memOK);
    if (!memOK) {
        return "";
    }
    
    const char *className = vm2->readString(objc_classname_addr, 1000);
    return className ? className : "";
}

uint64_t ObjcClassRuntimeInfo::trickAlignForClassRO(uint64_t objc_class_ro_addr) {
    // FIXME: address align
    if (objc_class_ro_addr % 8 != 0) {
        // FIXME: only allow 0, 8, check real align rules
        if ((objc_class_ro_addr & 0xf) <= 0x4) {
            objc_class_ro_addr = objc_class_ro_addr & ~(0xfllu);
        } else {
            objc_class_ro_addr = (objc_class_ro_addr & ~(0xfllu)) | 0x8;
        }
    }
    return objc_class_ro_addr;
}
