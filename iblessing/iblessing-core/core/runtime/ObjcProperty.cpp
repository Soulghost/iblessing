//
//  ObjcProperty.cpp
//  iblessing
//
//  Created by Renektonli on 2021/5/12.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "ObjcProperty.hpp"
#include "StringUtils.h"
#include <algorithm>
using namespace std;
using namespace iblessing;
/*
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
 
 std::string getter;
 std::string setter;
 
 bool isReadOnly;
 bool isDynamic;
 **/
ObjcProperty::ObjcProperty(struct ib_property_t property) {
    
    raw = property;
    name = property.name;
    attributeString = property.attributes;
    
    defaultGetter = name;
    defaultSetter = "set" + StringUtils::capitalized(name) + ":";
    
    isReadOnly = false;
    isDynamic = false;
    
    handleAttributeString();
}

std::string ObjcProperty::getter(){

    if (this->customGetter.empty()) {
        
        return this->customGetter;
    }
    return this->defaultGetter;
}

std::string ObjcProperty::setter(){

    if (this->customSetter.empty()) {
        
        return this->customSetter;
    }
    return this->defaultSetter;
}

void ObjcProperty::handleAttributeString() {
    
    attributes = StringUtils::split(attributeString,',');
    
    
    for (std::string att: attributes) {
        
        if (StringUtils::has_prefix(att, "R")) {
            isReadOnly = true;
        } else if (StringUtils::has_prefix(att, "D")) {
            isDynamic = true;
        } else if (StringUtils::has_prefix(att, "G")) {
            customGetter = att.substr(1);
        } else if (StringUtils::has_prefix(att, "S")) {
            customSetter = att.substr(1);
        }
    }
}

