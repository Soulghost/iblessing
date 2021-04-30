//
//  classdump.cpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "classdump.hpp"
#include <iblessing/mach-o/mach-o.hpp>
#include <iblessing/memory/memory.hpp>
#include <iblessing/objc/objc.hpp>
#include <iblessing/dyld/dyld.hpp>

using namespace std;
using namespace iblessing;

int classdump_main(int argc, const char **argv) {
    string filePath = "/Users/soulghost/Desktop/git/iblessing/iblessing/build/Debug-iphoneos/iblessing-sample.app/iblessing-sample";
    shared_ptr<MachO> macho = MachO::createFromFile(filePath);
    assert(macho->loadSync() == IB_SUCCESS);
    
    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);
    
    shared_ptr<Objc> objc = Objc::create(macho, memory);
    objc->loadClassList();
    objc->loadCategoryList();
    
    shared_ptr<Dyld> dyld = Dyld::create(macho, memory, objc);
    dyld->doBindAll();
    
    objc->realizeClasses([&](ObjcClassRuntimeInfo *info, uint64_t current, uint64_t total) {
        printf("[+] %s.h\n", info->className.c_str());
    });
    return 0;
}
