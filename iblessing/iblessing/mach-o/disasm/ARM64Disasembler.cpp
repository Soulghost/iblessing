//
//  ARM64Disasembler.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ARM64Disasembler.hpp"
#include <cassert>

using namespace std;
using namespace iblessing;

ARM64Disassembler::ARM64Disassembler() {
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    this->handle = handle;
}

void ARM64Disassembler::startDisassembly(uint8_t *code, uint64_t address, ARM64DisassemblerCallback callback) {
    bool stop = false;
    while (!stop) {
        // dis
        cs_insn *insn = nullptr;
        size_t count = cs_disasm(handle, code, 4, address, 0, &insn);
        ARM64PCRedirect *redirect = nullptr;
        if (count != 1) {
            // dummy insn
            cs_insn *dummy_insn = new cs_insn();
            dummy_insn->address = address;
            callback(false, dummy_insn, &stop, &redirect);
            delete dummy_insn;
            
            code += 4;
            address += 4;
            continue;
        } else {
            callback(true, insn, &stop, &redirect);
        }
        
        // free and go
        cs_free(insn, 1);
        insn = nullptr;
        
        if (redirect != nullptr) {
            code = redirect->code;
            address = redirect->address;
            delete redirect;
        } else {
            code += 4;
            address += 4;
        }
    }
}
