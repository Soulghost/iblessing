//
//  ScannerCommon.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ScannerCommon_hpp
#define ScannerCommon_hpp

typedef enum scanner_err {
    SC_ERR_OK = 0,
    SC_ERR_INVALID_BINARY,          // invalid binary file
    SC_ERR_MAP_FAILED,
    SC_ERR_UNSUPPORT_ARCH,          // only support aarch64 now
    SC_ERR_MACHO_MISSING_SEGMENT_TEXT,
    SC_ERR_MACHO_MISSING_SEGMENT_DYLD,
    SC_ERR_MACHO_MISSING_SEGMENT_SYMTAB,
    SC_ERR_MACHO_MISSING_SEGMENT_DYSYMTAB
} scanner_err;

#endif /* ScannerCommon_hpp */
