//
//  mach-o.cpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "mach-o.hpp"
#include "ScannerContext.hpp"

using namespace std;
using namespace iblessing;

shared_ptr<MachO> MachO::createFromFile(std::string filePath) {
    shared_ptr<MachO> macho = make_shared<MachO>(filePath);
    return macho;
}

ib_return_t MachO::loadSync() {
    shared_ptr<ScannerContext> sc = make_shared<ScannerContext>();
    scanner_err err = sc->setupWithBinaryPath(_filePath);
    if (err != SC_ERR_OK) {
        return IB_MACHO_LOAD_ERROR;
    }
    this->context = sc;
    return IB_SUCCESS;
}
