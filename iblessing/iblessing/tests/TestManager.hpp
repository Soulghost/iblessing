//
//  TestManager.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef TestManager_hpp
#define TestManager_hpp

#include "Object.hpp"

NS_IB_BEGIN

class TestManager {
public:
    virtual ~TestManager() {};
    static bool testAll();
};

NS_IB_END

#endif /* TestManager_hpp */
