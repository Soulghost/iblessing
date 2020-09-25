//
//  ScannerContext.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ScannerContext_hpp
#define ScannerContext_hpp

#include "Object.hpp"
#include "ScannerCommon.hpp"
#include "ScannerWorkDirManager.hpp"
#include "mach-universal.hpp"
#include "mach-machine.h"
#include <string>

NS_IB_BEGIN

class ScannerContext {
public:
    ScannerContext();
    
    std::string getBinaryPath();
    static scanner_err headerDetector(std::string binaryPath,
                                      uint8_t **mappedFileOut,    /** OUT */
                                      uint64_t *sizeOut,          /** OUT */
                                      ib_mach_header_64 **hdrOut  /** OUT */);
    static scanner_err headerDetector(uint8_t *mappedFile,        /** OUT */
                                      ib_mach_header_64 **hdrOut, /** OUT */
                                      uint64_t *archOffsetOut = nullptr, /** OUT */
                                      uint64_t *archSizeOut = nullptr    /** OUT */);
    scanner_err archiveStaticLibraryAndRetry(std::string binaryPath);
    scanner_err setupWithBinaryPath(std::string binaryPath, bool reentry = false);
    
private:
    std::string binaryPath;
    std::shared_ptr<ScannerWorkDirManager> workDirManager;
};

NS_IB_END

#endif /* ScannerContext_hpp */
