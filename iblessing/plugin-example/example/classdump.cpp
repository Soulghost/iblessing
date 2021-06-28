//
//  classdump.cpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "classdump.hpp"
#include "CoreFoundation.hpp"
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <iblessing-core/v2/objc/objc.hpp>
#include <iblessing-core/v2/dyld/dyld.hpp>

using namespace std;
using namespace iblessing;

int classdump_main(int argc, const char **argv) {
    string filePath = "/Users/soulghost/Desktop/git/iblessing/iblessing/build/Debug-iphoneos/iblessing-sample.app/iblessing-sample";
//    string filePath = "/opt/one-btn/tmp/apps/WeChat/Payload/WeChat";
    shared_ptr<MachO> macho = MachO::createFromFile(filePath);
    assert(macho->loadSync() == IB_SUCCESS);
    
    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);
    
    shared_ptr<Objc> objc = memory->objc;
    objc->loadClassList();
    objc->loadCategoryList();
    
    shared_ptr<Dyld> dyld = Dyld::create(macho, memory, objc);
    dyld->doBindAll();
    
    objc->realizeClasses([&](ObjcClassRuntimeInfo *info, uint64_t current, uint64_t total) {
        printf("[+] %s.h\n", info->className.c_str());
        printf("@interface %s", info->className.c_str());
        if (info->superClassInfo) {
            printf(" : %s\n", info->superClassInfo->className.c_str());
        } else {
            printf(" : ?\n");
        }
        
        for (ObjcMethod *method : info->methodList) {
            printf("%s (%s)", method->isClassMethod ? "+" : "-", CoreFoundation::resolveTypeEncoding(method->argTypes[0]).c_str());
            printf("%s;\n", method->name.c_str());
        }
        
        printf("\n");
        
        for (ObjcIvar *ivar : info->ivarList) {
            printf("@property (nonatomic) %s %s%s;\n", ivar->typeName.c_str(), ivar->type == IvarTypeObjcClass ? "*" : "?", ivar->raw.name);
        }
        printf("@end\n");
    });
    return 0;
}
