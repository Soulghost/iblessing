//
//  iblessing_core.cpp
//  iblessing-core
//
//  Created by Soulghost on 2021/5/3.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include <iostream>
#include "iblessing_core.hpp"
#include "iblessing_corePriv.hpp"

void iblessing_core::HelloWorld(const char * s)
{
    iblessing_corePriv *theObj = new iblessing_corePriv;
    theObj->HelloWorldPriv(s);
    delete theObj;
};

void iblessing_corePriv::HelloWorldPriv(const char * s) 
{
    std::cout << s << std::endl;
};

