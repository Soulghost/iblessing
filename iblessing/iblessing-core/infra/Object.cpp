//
//  IBObject.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include <iblessing-core/infra/Object.hpp>
#include <assert.h>

using namespace iblessing;

Object::Object() {
    _referenceCount = 1;
}

Object::~Object() {
    
}

void Object::retain() {
    assert(_referenceCount > 0);
    ++_referenceCount;
}

void Object::release() {
    assert(_referenceCount > 0);
    --_referenceCount;
    if (_referenceCount == 0) {
        delete this;
    }
}
