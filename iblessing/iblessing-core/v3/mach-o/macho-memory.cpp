//
//  macho-memory.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/9/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "macho-memory.hpp"

NS_IB_BEGIN

namespace MachoMemoryUtils {

char* uc_read_string(uc_engine *uc, uint64_t address, uint64_t limit) {
    char *charBuf = (char *)malloc(limit + 1);
    uint64_t offset = 0;
    uint64_t unPrintCount = 0;
    bool ok = true;
    while (offset < limit && (ok = (uc_mem_read(uc, address + offset, charBuf + offset, sizeof(char))) == UC_ERR_OK)) {
        if (charBuf[offset] == 0) {
            break;
        }
        if (!(charBuf[offset] >= 0x20 && charBuf[offset] <= 0x7E)) {
            unPrintCount++;
            if (unPrintCount > 10) {
                ok = false;
                break;
            }
        }
        offset++;
    }
    
    if (!ok) {
        free(charBuf);
        return NULL;
    }
    
    charBuf[offset] = 0;
    char *strBuffer = (char *)malloc(offset + 1);
    memcpy(strBuffer, charBuf, offset + 1);
    free(charBuf);
    return strBuffer;
}

};

NS_IB_END
