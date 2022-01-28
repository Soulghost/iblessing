//
//  DarwinService.cpp
//  DarwinService
//
//  Created by soulghost on 2020/7/11.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include <os/log.h>

#include <DriverKit/IOUserServer.h>
#include <DriverKit/IOLib.h>

#include "DarwinService.h"

kern_return_t
IMPL(DarwinService, Start)
{
    kern_return_t ret;
    ret = Start(provider, SUPERDISPATCH);
    os_log(OS_LOG_DEFAULT, "Hello World");
    return ret;
}
