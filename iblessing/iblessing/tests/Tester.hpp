//
//  Tester.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef Tester_hpp
#define Tester_hpp

#include "Object.hpp"

NS_IB_BEGIN

class Tester {
public:
    virtual ~Tester() {};
    virtual bool start() = 0;
};

NS_IB_END

#endif /* Tester_hpp */
