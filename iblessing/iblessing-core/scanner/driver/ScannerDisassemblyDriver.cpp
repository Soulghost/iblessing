//
//  ScannerDisassemblyDriver.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ScannerDisassemblyDriver.hpp"

using namespace std;
using namespace iblessing;

void ScannerDisassemblyDriver::subscribeDisassemblyEvent(void *scanner, ARM64DisassemblerCallback callback) {
    for (auto it = subscribers.begin(); it != subscribers.end(); it++) {
        if (scanner == it->first) {
            return;
        }
    }
    
    subscribers.push_back({scanner, callback});
}

void ScannerDisassemblyDriver::unsubscribeDisassemblyEvent(void *scanner) {
    for (auto it = subscribers.begin(); it != subscribers.end(); it++) {
        if (it->first == scanner) {
            subscribers.erase(it);
            break;
        }
    }
}

void ScannerDisassemblyDriver::startDisassembly(uint8_t *code, uint64_t startAddress, uint64_t endAddress, ARM64DisassemblerCallback callback) {
    ARM64Disassembler disasm;
    disasm.startDisassembly(code, startAddress, [&](bool success, cs_insn *insn, bool *stop, ARM64PCRedirect **redirect) {
        if (callback) {
            callback(success, insn, stop, redirect);
        }
        
        if (insn->address >= endAddress) {
            printf("\n[*] ScannerDisassemblyDriver - reach to end of __text, stop\n");
            *stop = true;
        }
        
        for (auto it = subscribers.begin(); it != subscribers.end(); it++) {
            it->second(success, insn, stop, redirect);
        }
    });
}
