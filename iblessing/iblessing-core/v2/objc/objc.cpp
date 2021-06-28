//
//  objc.cpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "objc.hpp"

using namespace std;
using namespace iblessing;

Objc::Objc(shared_ptr<MachO> macho, Memory *memory) {
    shared_ptr<ObjcRuntime> rt = make_shared<ObjcRuntime>(macho->context->symtab, memory->virtualMemory);
    this->runtime = rt;
    this->macho = macho;
    this->memory = memory;
    
    shared_ptr<VirtualMemory> fileMemory = memory->fileMemory;
    rt->classlist_addr = fileMemory->objc_classlist_addr;
    rt->classlist_size = fileMemory->objc_classlist_size;
    rt->catlist_addr = fileMemory->objc_catlist_addr;
    rt->catlist_size = fileMemory->objc_catlist_size;
}

shared_ptr<Objc> Objc::create(std::shared_ptr<MachO> macho, Memory *memory) {
    return make_shared<Objc>(macho, memory);
}

shared_ptr<ObjcRuntime> Objc::getRuntime() {
    return this->runtime;
}

ib_return_t Objc::loadClassList() {
    shared_ptr<ObjcRuntime> rt = this->runtime;
    rt->loadClassList(rt->classlist_addr, rt->classlist_size);
    return IB_SUCCESS;
}

ib_return_t Objc::loadCategoryList() {
    shared_ptr<ObjcRuntime> rt = this->runtime;
    if (rt->catlist_addr != 0 && rt->catlist_size != 0) {
        rt->loadCatList(macho->context->symtab, rt->catlist_addr, rt->catlist_size);
    }
    return IB_SUCCESS;
}

ib_return_t Objc::realizeClasses(ClassRealizeCallback callback) {
    unordered_map<string, uint64_t> &classList = runtime->classList;
    uint64_t count = 0, total = classList.size();
    for (auto it = classList.begin(); it != classList.end(); it++) {
        if (it->second == 0) {
//            printf("\t[+] skip bad class %s\n", it->first.c_str());
            continue;
        }
        ObjcClassRuntimeInfo *classInfo = runtime->getClassInfoByAddress(it->second);
        count++;
        callback(classInfo, count, total);
    }
    return IB_SUCCESS;
}
