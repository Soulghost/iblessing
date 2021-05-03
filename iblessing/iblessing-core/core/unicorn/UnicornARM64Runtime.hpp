//
//  UnicornARM64Runtime.hpp
//  iblessing
//
//  Created by soulghost on 2020/6/2.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef UnicornARM64Runtime_hpp
#define UnicornARM64Runtime_hpp

#include <iblessing-core/infra/Object.hpp>

NS_IB_BEGIN

class UnicornARM64Runtime {
public:
    static void testFunction(uint64_t address, uint64_t endaddr);
};

NS_IB_END

#endif /* UnicornARM64Runtime_hpp */
