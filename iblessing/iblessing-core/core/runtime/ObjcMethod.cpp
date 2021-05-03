//
//  ObjcMethod.cpp
//  iblessing
//
//  Created by soulghost on 2020/3/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcMethod.hpp"
#include "VirtualMemory.hpp"
#include "SymbolTable.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include "ObjcClass.hpp"

using namespace std;
using namespace iblessing;

ObjcMethod* ObjcMethod::createDummy(std::string name) {
    ObjcMethod *m = new ObjcMethod();
    m->name = name;
    m->isDummy = true;
    m->classInfo = nullptr;
    return m;
}

string ObjcMethod::desc() {
    string className;
    if (classInfo) {
        className = classInfo->className;
    }
    
    string prefix = isClassMethod ? "+" : "-";
    return StringUtils::format("%s[%s %s]", prefix.c_str(), className.c_str(), name.c_str());
}
