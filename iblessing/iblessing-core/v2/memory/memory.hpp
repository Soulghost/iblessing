//
//  memory.hpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef memory_hpp
#define memory_hpp

#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/core/memory/VirtualMemory.hpp>
#include <iblessing-core/core/memory/VirtualMemoryV2.hpp>

namespace iblessing {

class Objc;

class Memory {
public:
    Memory(std::shared_ptr<MachO> macho) : macho(macho) {}

    static std::shared_ptr<Memory> createFromMachO(std::shared_ptr<MachO> macho);
    ib_return_t loadSync();
    ib_return_t copyToUCEngine(uc_engine *uc);
    
    std::shared_ptr<VirtualMemory> fileMemory;
    std::shared_ptr<VirtualMemoryV2> virtualMemory;
    std::shared_ptr<Objc> objc;
    
protected:
    std::shared_ptr<MachO> macho;
};

};

#endif /* memory_hpp */
