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

ObjcProperty::ObjcProperty(struct ib_property_t property) {
    
    raw = property;
    name = property.name;
    attributeString = property.attributes;
    
    defaultGetter = name;
    defaultSetter = "set" + StringUtils::capitalized(name) + ":";
    assignedType = "assign";
    
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
    attributes.pop_back();//移除变量名 防止误判
    std::string typeString = attributes.front();
    
    if (typeString.find("TB") != std::string::npos) {
        type = "BOOL";
    } else if (typeString.find("Tc") != std::string::npos) {
        type = "char";
    } else if (typeString.find("Td") != std::string::npos) {
        type = "double";
    } else if (typeString.find("Ti") != std::string::npos) {
        type = "int";
    } else if (typeString.find("Tf") != std::string::npos) {
        type = "float";
    } else if (typeString.find("Tl") != std::string::npos) {
        type = "long";
    } else if (typeString.find("Ts") != std::string::npos) {
        type = "short";
    } else if (typeString.find("TI") != std::string::npos) {
        type = "unsigned";
    } else if (typeString.find("T@\"") != std::string::npos) {
        std::size_t front = typeString.find("T@\"");
        std::size_t back = typeString.rfind("\"", typeString.length());
        type = typeString.substr(front+3, back-3);
    } else if (typeString.find("T@") != std::string::npos) {
        type = "id";
    }
    
    for (std::string att: attributes) {
        
        if (StringUtils::has_prefix(att, "R")) {
            isReadOnly = true;
        } else if (StringUtils::has_prefix(att, "D")) {
            isDynamic = true;
        } else if (StringUtils::has_prefix(att, "N")) {
            isNonatomic = true;
        } else if (StringUtils::has_prefix(att, "G")) {
            customGetter = att.substr(1);
        } else if (StringUtils::has_prefix(att, "S")) {
            customSetter = att.substr(1);
        } else if (StringUtils::has_prefix(att, "C")) {
            assignedType = "copy";
        } else if (StringUtils::has_prefix(att, "&")) {
            assignedType = "retain";
        } else if (StringUtils::has_prefix(att, "&")) {
            assignedType = "weak";
        }
    }
}

