//
//  ARM64Disasembler.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ARM64Disasembler_hpp
#define ARM64Disasembler_hpp

#include <iblessing-core/infra/Object.hpp>
#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <functional>

NS_IB_BEGIN

class ARM64PCRedirect {
public:
    uint64_t address;
    uint8_t *code;
    
    ARM64PCRedirect(uint64_t address, uint8_t *code) :
        address(address), code(code) {}
};

typedef std::function<void (bool success, cs_insn *insn, bool *stop, ARM64PCRedirect **redirect)> ARM64DisassemblerCallback;

class ARM64Disassembler {
public:
    ARM64Disassembler();
    void startDisassembly(uint8_t *code, uint64_t address, ARM64DisassemblerCallback callback);
    
private:
    csh handle;
};

NS_IB_END

#endif /* ARM64Disasembler_hpp */
