//
//  ObjcIvar.cpp
//  iblessing
//
//  Created by soulghost on 2020/3/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcIvar.hpp"

using namespace std;
using namespace iblessing;

ObjcIvar::ObjcIvar(struct ib_ivar_t ivar) {
    raw = ivar;
}
