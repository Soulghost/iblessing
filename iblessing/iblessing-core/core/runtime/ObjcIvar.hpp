//
//  ObjcIvar.hpp
//  iblessing
//
//  Created by soulghost on 2020/3/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcIvar_hpp
#define ObjcIvar_hpp

#include <iblessing-core/infra/Object.hpp>
#include <string>

NS_IB_BEGIN

enum IvarType {
    IvarTypeUnKnown = 0,
    IvarTypeObjcClass,
    IvarTypePrimary
};

class ObjcClassRuntimeInfo;

struct ib_ivar_t {
    int32_t *offset;
    const char *name;
    const char *type;
    // alignment is sometimes -1; use alignment() instead
    uint32_t alignment_raw;
    uint32_t size;
};

class ObjcIvar : public Object {
public:
    struct ib_ivar_t raw;
    ObjcClassRuntimeInfo *clazz;
    uint64_t offset;
    IvarType type;
    std::string typeName;
    
    ObjcIvar(struct ib_ivar_t ivar);
};

class ObjcIvarObject : public Object {
public:
    ObjcIvar *info;
    void *data;
    
    ObjcIvarObject(ObjcIvar *info): info(info) {}
};

NS_IB_END

#endif /* ObjcIvar_hpp */
