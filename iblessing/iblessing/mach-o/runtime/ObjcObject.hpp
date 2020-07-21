//
//  ObjcObject.hpp
//  iblessing
//
//  Created by soulghost on 2020/3/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcObject_hpp
#define ObjcObject_hpp

#include "Object.hpp"
#include "Vector.hpp"
#include <unordered_map>
#include "ObjcClass.hpp"

NS_IB_BEGIN

class ObjcObject {
public:
    ObjcClassRuntimeInfo *isa;
    
    ObjcObject(ObjcClassRuntimeInfo *isa): isa(isa) {};
};

NS_IB_END

#endif /* ObjcObject_hpp */
