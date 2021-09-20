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

class MachOModule;
class MachOLoader;

typedef std::function<uint64_t (std::string symbolName, uint64_t symbolAddr)> DyldBindHook;

class Dyld {
public:
    static std::map<std::string, DyldBindHook> bindHooks;
    
    Dyld(std::shared_ptr<MachO> macho, std::shared_ptr<Memory> memory, std::shared_ptr<Objc> objc = nullptr) :
        macho(macho), memory(memory), objc(objc) {};
    static std::shared_ptr<Dyld> create(std::shared_ptr<MachO> macho, std::shared_ptr<Memory> memory, std::shared_ptr<Objc> objc = nullptr);
    
    void doBindAll(DyldBindHandler handler = nullptr);
    static uint64_t bindAt(std::shared_ptr<MachOModule> module, std::shared_ptr<MachOLoader> loader, int64_t libraryOrdinal, const char *symbolName, uint64_t addr, uint64_t addend, uint8_t type);
    static uint64_t doFastLazyBind(std::shared_ptr<MachOModule> module, std::shared_ptr<MachOLoader> loader, uint64_t lazyBindingInfoOffset);
    
protected:
    std::shared_ptr<MachO> macho;
    std::shared_ptr<Memory> memory;
    std::shared_ptr<Objc> objc;
};

};

#endif /* dyld_hpp */
