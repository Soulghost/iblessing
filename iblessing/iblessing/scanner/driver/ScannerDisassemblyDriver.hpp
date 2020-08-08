//
//  ScannerDisassemblyDriver.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ScannerDisassemblyDriver_hpp
#define ScannerDisassemblyDriver_hpp

#include "ARM64Disasembler.hpp"
#include <vector>

NS_IB_BEGIN

class ScannerDisassemblyDriver {
public:
    void subscribeDisassemblyEvent(void *scanner, ARM64DisassemblerCallback callback);
    void unsubscribeDisassemblyEvent(void *scanner);
    void startDisassembly(uint8_t *code, uint64_t startAddress, uint64_t endAddress, ARM64DisassemblerCallback callback = 0);
    
private:
    // traverse >>> find, so we use vector instead of map
    std::vector<std::pair<void *, ARM64DisassemblerCallback>> subscribers;
};

NS_IB_END

#endif /* ScannerDisassemblyDriver_hpp */
