//
//  dyld.hpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef dyld_hpp
#define dyld_hpp

#include <iblessing-core/v2/memory/memory.hpp>
#include <iblessing-core/v2/objc/objc.hpp>
#include <iblessing-core/core/dyld/DyldSimulator.hpp>

namespace iblessing {

class Dyld {
public:
    Dyld(std::shared_ptr<MachO> macho, std::shared_ptr<Memory> memory, std::shared_ptr<Objc> objc = nullptr) :
        macho(macho), memory(memory), objc(objc) {};
    static std::shared_ptr<Dyld> create(std::shared_ptr<MachO> macho, std::shared_ptr<Memory> memory, std::shared_ptr<Objc> objc = nullptr);
    
    void doBindAll(DyldBindHandler handler = nullptr);
    
protected:
    std::shared_ptr<MachO> macho;
    std::shared_ptr<Memory> memory;
    std::shared_ptr<Objc> objc;
};

};

#endif /* dyld_hpp */
