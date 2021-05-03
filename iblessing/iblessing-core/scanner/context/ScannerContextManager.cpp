//
//  ScannerContext.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ScannerContextManager.hpp"
#include <iblessing-core/v2/util/termcolor.h>

using namespace std;
using namespace iblessing;

ScannerContextManager* ScannerContextManager::_instance = nullptr;

ScannerContextManager* ScannerContextManager::globalManager() {
    if (ScannerContextManager::_instance == nullptr) {
        ScannerContextManager::_instance = new ScannerContextManager();
    }
    return ScannerContextManager::_instance;
}

ScannerContext* ScannerContextManager::getContextByBinaryPath(string binaryPath) {
    cout << "[*] ScannerContextManager get context for file " << binaryPath << endl;
    if (contextMap.find(binaryPath) != contextMap.end()) {
        cout << "[+] ScannerContextManager get context hit cache for file " << binaryPath << endl;
        return contextMap[binaryPath];
    }
    
    ScannerContext *ctx = new ScannerContext();
    scanner_err err = ctx->setupWithBinaryPath(binaryPath);
    if (err != SC_ERR_OK) {
        switch (err) {
            case SC_ERR_INVALID_BINARY:
                cout << termcolor::red << "[-] ScannerContextManager Error: invalid binary file " << binaryPath;
                cout << termcolor::reset << endl;
                return nullptr;
            case SC_ERR_MAP_FAILED:
                cout << termcolor::red << "[-] ScannerContextManager Error: mmap failed, please try again";
                cout << termcolor::reset << endl;
                return nullptr;
            case SC_ERR_UNSUPPORT_ARCH:
                cout << termcolor::red << "[-] ScannerContextManager Error: unsupport arch, only support aarch64 now";
                cout << termcolor::reset << endl;
                return nullptr;
            case SC_ERR_MACHO_MISSING_SEGMENT_DYLD:
                cout << termcolor::red << "[-] ScannerContextManager Error: DYLD_INFO_ONLY segment not found, maybe the mach-o file is corrupted";
                cout << termcolor::reset << endl;
                return nullptr;
            case SC_ERR_MACHO_MISSING_SEGMENT_TEXT:
                cout << termcolor::red << "[-] ScannerContextManager Error: __TEXT segment not found, maybe the mach-o file is corrupted";
                cout << termcolor::reset << endl;
                return nullptr;
            case SC_ERR_MACHO_MISSING_SEGMENT_SYMTAB:
                cout << termcolor::red << "[-] ScannerContextManager Error: SYMTAB segment not found, maybe the mach-o file is corrupted";
                cout << endl;
                return nullptr;
            case SC_ERR_MACHO_MISSING_SEGMENT_DYSYMTAB:
                cout << termcolor::red << "[-] ScannerContextManager Error: DYSYMTAB segment not found, maybe the mach-o file is corrupted";
                cout << endl;
                return nullptr;
            default:
                cout << termcolor::red << "[-] ScannerContextManager Error: ?";
                return nullptr;
        }
    }
    
    contextMap[binaryPath] = ctx;
    cout << "[*] ScannerContextManager create new context for file " << binaryPath << endl;
    return ctx;
}


