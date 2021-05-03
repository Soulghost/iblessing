//
//  ObjcObject.hpp
//  iblessing
//
//  Created by soulghost on 2020/3/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcObject_hpp
#define ObjcObject_hpp

#include <unordered_map>
#include <iblessing-core/infra/Object.hpp>
#include <iblessing-core/infra/Vector.hpp>
#include <iblessing-core/core/runtime/ObjcClass.hpp>

NS_IB_BEGIN

class ObjcObject {
public:
    ObjcClassRuntimeInfo *isa;
    
    ObjcObject(ObjcClassRuntimeInfo *isa): isa(isa) {};
};

NS_IB_END

#endif /* ObjcObject_hpp */
