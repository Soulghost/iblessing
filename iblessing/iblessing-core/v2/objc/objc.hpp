//
//  objc.hpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef objc_hpp
#define objc_hpp

#include <iblessing-core/v2/memory/memory.hpp>
#include <iblessing-core/core/runtime/ObjcRuntime.hpp>

namespace iblessing {

typedef std::function<void (ObjcClassRuntimeInfo *classInfo, uint64_t current, uint64_t total)> ClassRealizeCallback;

class Objc {
public:
    Objc(std::shared_ptr<MachO> macho, Memory *memory);
    
    static std::shared_ptr<Objc> create(std::shared_ptr<MachO> macho, Memory *memory);
    ib_return_t loadClassList();
    ib_return_t loadCategoryList();
    
    std::shared_ptr<ObjcRuntime> getRuntime();
    ib_return_t realizeClasses(ClassRealizeCallback callback);
    
protected:
    std::shared_ptr<ObjcRuntime> runtime;
    std::shared_ptr<MachO> macho;
    Memory *memory;
};

};

#endif /* objc_hpp */
