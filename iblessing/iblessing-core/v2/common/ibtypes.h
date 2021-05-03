//
//  iblessing-base.h
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef iblessing_base_h
#define iblessing_base_h

#include <stdio.h>
#include <string>
#include <memory>

typedef int ib_return_t;
#define IB_SUCCESS 0
#define IB_MACHO_LOAD_ERROR 1
#define IB_MEMORY_LOAD_ERROR_INVALID_MACHO 2
#define IB_INVALID_ARGUMENTS 3
#define IB_UNINIT_MODULE 4
#define IB_MEMORY_COPYOUT_ERROR 5
#define IB_MEMORY_MAPPING_ERROR 6
#define IB_OBJC_DATA_LOAD_ERROR 7

#endif /* iblessing_base_h */
