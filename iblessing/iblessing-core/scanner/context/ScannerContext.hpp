//
//  ScannerContext.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ScannerContext_hpp
#define ScannerContext_hpp

#include <iblessing-core/infra/Object.hpp>
#include <iblessing-core/scanner/context/ScannerWorkDirManager.hpp>
#include <iblessing-core/core/polyfill/mach-universal.hpp>
#include <iblessing-core/core/polyfill/mach-machine.h>
#include <iblessing-core/core/memory/VirtualMemory.hpp>
#include <iblessing-core/core/memory/VirtualMemoryV2.hpp>
#include <iblessing-core/core/symtab/StringTable.hpp>
#include <iblessing-core/core/symtab/SymbolTable.hpp>
#include <iblessing-core/core/runtime/ObjcRuntime.hpp>

NS_IB_BEGIN

typedef enum scanner_err {
    SC_ERR_OK = 0,
    SC_ERR_UNKNOWN,
    SC_ERR_NEED_ARCHIVE_LIPO,
    SC_ERR_NEED_ARCHIVE_NOLIPO,
    SC_ERR_INVALID_ARGUMENTS,
    SC_ERR_INVALID_BINARY,          // invalid binary file
    SC_ERR_RESET_WORK_DIR,
    SC_ERR_MAP_FAILED,
    SC_ERR_UNSUPPORT_ARCH,          // only support aarch64 now
    SC_ERR_MACHO_MISSING_SEGMENT_TEXT,
    SC_ERR_MACHO_MISSING_SEGMENT_DYLD,
    SC_ERR_MACHO_MISSING_SEGMENT_SYMTAB,
    SC_ERR_MACHO_MISSING_SEGMENT_DYSYMTAB
} scanner_err;

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
    scanner_err archiveStaticLibraryAndRetry(std::string binaryPath, scanner_err analyzeError);
    scanner_err setupWithBinaryPath(std::string binaryPath, bool reentry = false);
    
    std::shared_ptr<VirtualMemory> fileMemory;
    std::shared_ptr<VirtualMemoryV2> readonlyMemory;
    std::shared_ptr<StringTable> strtab;
    std::shared_ptr<SymbolTable> symtab;
    std::shared_ptr<ObjcRuntime> objcRuntime;
    
private:
    std::string binaryPath;
    std::shared_ptr<ScannerWorkDirManager> workDirManager;
};

NS_IB_END

#endif /* ScannerContext_hpp */
