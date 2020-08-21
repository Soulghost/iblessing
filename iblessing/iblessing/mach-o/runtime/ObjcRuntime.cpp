//
//  ObjcRuntime.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcRuntime.hpp"
#include "VirtualMemory.hpp"
#include "SymbolTable.hpp"
#include "termcolor.h"
#include "StringUtils.h"

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
    VirtualMemory *vm = VirtualMemory::progressDefault();
    uint64_t *classAddrs = (uint64_t *)vm->readBySize(vmaddr, size);
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
