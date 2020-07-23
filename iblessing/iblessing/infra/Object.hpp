//
//  IBObject.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef IBObject_hpp
#define IBObject_hpp

#include <cstdio>
#include <iostream>
#include <cassert>
#include "CommonDefines.hpp"

NS_IB_BEGIN

class Object {
public:
    virtual ~Object();
    
    void retain();
    void release();
    unsigned int getReferenceCount() const;
    
protected:
    Object();
    
    unsigned int _referenceCount;
};

NS_IB_END

#endif /* IBObject_hpp */
