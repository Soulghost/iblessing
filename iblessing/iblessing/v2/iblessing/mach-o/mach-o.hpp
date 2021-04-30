//
//  mach-o.hpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef mach_o_hpp
#define mach_o_hpp

#include <stdio.h>
#include <iblessing/common/ibtypes.h>
#include "ScannerContext.hpp"

namespace iblessing {

class MachO {
public:
    MachO(std::string filePath) : _filePath(filePath) {}
    
    std::shared_ptr<ScannerContext> context;
    
    static std::shared_ptr<MachO> createFromFile(std::string filePath);
    ib_return_t loadSync();
    
private:
    std::string _filePath;
};

};

#endif /* mach_o_hpp */
