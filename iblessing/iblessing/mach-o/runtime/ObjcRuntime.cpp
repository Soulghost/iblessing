//
//  ObjcRuntime.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcRuntime.hpp"
#include "VirtualMemoryV2.hpp"
#include "SymbolTable.hpp"
#include "termcolor.h"
#include "StringUtils.h"
#include "ObjcCategory.hpp"

using namespace std;
using namespace iblessing;

ObjcRuntime* ObjcRuntime::_instance = nullptr;

ObjcRuntime::ObjcRuntime() {
    
}

ObjcRuntime* ObjcRuntime::getInstance() {
    if (ObjcRuntime::_instance == nullptr) {
        ObjcRuntime::_instance = new ObjcRuntime();
    }
    return ObjcRuntime::_instance;
}

ObjcClassRuntimeInfo* ObjcRuntime::getClassInfoByAddress(uint64_t address, bool needRealize) {
    // check address
    if (address2RuntimeInfo.find(address) != address2RuntimeInfo.end()) {
        return address2RuntimeInfo[address];
    }
    
    // check external
    if (externalClassRuntimeInfo.find(address) != externalClassRuntimeInfo.end()) {
        return externalClassRuntimeInfo[address];
    }
    
    if (!needRealize) {
        return nullptr;
    }
    
    ObjcClassRuntimeInfo *info = ObjcClassRuntimeInfo::realizeFromAddress(address);
    if (!info) {
        return nullptr;
    }
    classList[info->className] = address;
    return info;
}

bool ObjcRuntime::isClassObjectAtAddress(uint64_t address) {
    return address2RuntimeInfo.find(address) != address2RuntimeInfo.end();
}

bool ObjcRuntime::isValidClassInfo(ObjcClassRuntimeInfo *info) {
    return runtimeInfo2address.find(info) != runtimeInfo2address.end();
}

void ObjcRuntime::loadClassList(uint64_t vmaddr, uint64_t size) {
    VirtualMemoryV2 *vm = VirtualMemoryV2::progressDefault();
    uint64_t *classAddrs = (uint64_t *)vm->readBySize(vmaddr, size);
    if (!classAddrs) {
        return;
    }
    
    uint64_t count = size / sizeof(void *);
    classList.clear();
    for (int i = 0; i < count; i++) {
        uint64_t class_addr = *classAddrs;
        std::string className = ObjcClassRuntimeInfo::classNameAtAddress(class_addr);
        if (className.length() == 0) {
            continue;
        }
        classList[className] = class_addr;
        classAddrs += 1;
    }
}

void ObjcRuntime::loadCatList(uint64_t vmaddr, uint64_t size) {
    categoryList.clear();
    
    VirtualMemoryV2 *vm = VirtualMemoryV2::progressDefault();
    uint64_t *cateAddrs = (uint64_t *)vm->readBySize(vmaddr, size);
    if (!cateAddrs) {
        return;
    }
    
    uint64_t count = size / sizeof(void *);
    for (int i = 0; i < count; i++) {
        uint64_t cateAddr = *cateAddrs;
        shared_ptr<ObjcCategory> category = ObjcCategory::loadFromAddress(cateAddr);
        categoryList.push_back(category);
        cateAddrs += 1;
    }
}

uint64_t ObjcRuntime::getClassAddrByName(string className) {
    if (strncmp(className.c_str(), "_OBJC_CLASS_$", strlen("_OBJC_CLASS_$")) == 0) {
        vector<string> parts = StringUtils::split(className, '_');
        className = parts[parts.size() - 1];
    }
    if (classList.find(className) != classList.end()) {
        return classList[className];
    }
    return 0;
}

ObjcClassRuntimeInfo* ObjcRuntime::getClassInfoByName(std::string className) {
    uint64_t addr = getClassAddrByName(className);
    if (!addr) {
        return nullptr;
    }
    return getClassInfoByAddress(addr);
}

ObjcClassRuntimeInfo* ObjcRuntime::evalReturnForIvarGetter(ObjcClassRuntimeInfo *targetClass, std::string getterSEL) {
    ObjcIvar *ivar = targetClass->name2ivar[getterSEL];
    if (ivar && ivar->type == IvarTypeObjcClass) {
        uint64_t classAddr = getClassAddrByName(ivar->typeName);
        return classAddr ? getClassInfoByAddress(classAddr) : nullptr;
    }
    return nullptr;
}

bool ObjcRuntime::isExistMethod(string methodPrefix, string classExpr, string detectedSEL) {
    ObjcClassRuntimeInfo *classInfo = getClassInfoByName(classExpr);
    if (!classInfo) {
        // try external class
        if (name2ExternalClassRuntimeInfo.find(classExpr) != name2ExternalClassRuntimeInfo.end()) {
            return true;
        }
        return false;
    }
    
    ObjcMethod *method = classInfo->getMethodBySEL(detectedSEL);
    if (!method) {
        return false;
    }
    
    string validMethodPrefix = method->isClassMethod ? "+" : "-";
    return validMethodPrefix == methodPrefix;
}

ObjcMethod* ObjcRuntime::inferNearestMethod(string methodPrefix, string classExpr, string detectedSEL) {
    ObjcClassRuntimeInfo *classInfo = getClassInfoByName(classExpr);
    if (!classInfo || classInfo->isExternal) {
        return nullptr;
    }
    
    ObjcMethod *method = classInfo->getMethodBySEL(detectedSEL);
    if (!method || !method->classInfo) {
        return nullptr;
    }
    
    return method;
}
