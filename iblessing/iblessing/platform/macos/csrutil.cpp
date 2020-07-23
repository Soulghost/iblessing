//
//  csrutil.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "csrutil.hpp"
#include "csr.h"

using namespace std;
using namespace iblessing;

bool CSRUtil::isSIPon() {
    csr_config_t config;
    if (csr_get_active_config(&config) != 0) {
        printf("[-] error: failed to retrieve system integrity configuration.\n");
        // treat as off
        return false;
    }
    
    // from /usr/bin/csrutil
    config = config & 0xF9u;
    if (config > 102) {
        if (config == 103) {
            return false;
        }
        
        if (config == 119) {
            return false;
        }
        
        if (!(config & 0x10)) {
            return false;
        }
    }
    
    if (!config) {
        return true;
    }
    
    if (config != 16) {
        if (!(config & 0x10)) {
            return false;
        }
    }
    
    return true;
}
