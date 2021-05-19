//
//  ObjcProperty.hpp
//  iblessing
//
//  Created by Renektonli on 2021/5/12.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef ObjcProperty_hpp
#define ObjcProperty_hpp

#include <stdio.h>

#include "Object.hpp"
#include <string>
#include <vector>

NS_IB_BEGIN
struct ib_property_t {
    const char *name;
    const char *attributes;
};

class ObjcClassRuntimeInfo;

class ObjcProperty : public Object {
public:
    
    struct ib_property_t raw;
    ObjcClassRuntimeInfo *clazz;
    std::string name;
    std::string attributeString;
    std::string type;
    std::vector<std::string> attributes;
    
    std::string defaultGetter;
    std::string defaultSetter;
    
    std::string customGetter;
    std::string customSetter;
    
    std::string assignedType;
    
    bool isReadOnly;
    bool isDynamic;
    bool isNonatomic;
    
    ObjcProperty(struct ib_property_t property);
    std::string getter();
    std::string setter();
    std::string description();
private:
    void handleAttributeString();
    std::string getTypeWithTypeSign(std::string typeSign);
};
NS_IB_END
#endif /* ObjcProperty_hpp */
