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
#include <sstream>
using namespace std;
using namespace iblessing;

ObjcProperty::ObjcProperty(struct ib_property_t property) {
    
    raw = property;
    name = property.name;
    attributeString = property.attributes;
    
    defaultGetter = name;
    defaultSetter = "set" + StringUtils::capitalized(name) + ":";
    //assignedType = "assign";
    
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
    //attributes.pop_back();//移除变量名 防止误判
    std::string typeString = attributes.front();
    
    type = this->getTypeWithTypeSign(typeString);
    
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
        } else if (StringUtils::has_prefix(att, "W")) {
            assignedType = "weak";
        }
    }
}

std::string ObjcProperty::getTypeWithTypeSign(std::string typeSign) {
    
    std::string type;
    if (typeSign.find("TB") != std::string::npos) {
        type = "_Bool";
    } else if (typeSign.find("Tc") != std::string::npos) {
        type = "char";
    } else if (typeSign.find("TC") != std::string::npos) {
        type = "unsigned char";
    } else if (typeSign.find("Td") != std::string::npos) {
        type = "double";
    } else if (typeSign.find("Ti") != std::string::npos) {
        type = "int";
    } else if (typeSign.find("TI") != std::string::npos) {
        type = "unsigned int";
    } else if (typeSign.find("Tf") != std::string::npos) {
        type = "float";
    } else if (typeSign.find("Tl") != std::string::npos) {
        type = "long";
    } else if (typeSign.find("Ts") != std::string::npos) {
        type = "short";
    } else if (typeSign.find("Tq") != std::string::npos) {
        type = "long long";
    } else if (typeSign.find("TQ") != std::string::npos) {
        type = "unsigned long long";
    } else if (typeSign.find("T#") != std::string::npos) {
        type = "Class";
    } else if (typeSign.find("T:") != std::string::npos) {
        type = "SEL";
    } else if (typeSign.find("T@\"") != std::string::npos) {
        std::size_t front = typeSign.find("T@\"");
        std::size_t back = typeSign.rfind("\"", typeSign.length());
        type = typeSign.substr(front+3, back-3)+" *";
    } else if (typeSign.find("T@") != std::string::npos) {
        type = "id";
    } else if (typeSign.find("T{") != std::string::npos) {//struct
        type = "id";
    }
    return type;
}

std::string ObjcProperty::handleStructWithTypeSign(std::string typeSign) {
    if (typeSign.find("T{") != std::string::npos) {//struct
        type = "id";
    }
    return "";
}

std::string ObjcProperty::description() {
    
    std::string nonatomic = isNonatomic?"nonatomic":"atomic";
    std::string readOnly = isReadOnly?", readonly":"";
    std::string getter = customGetter.empty()?"":", getter="+customGetter;
    std::string setter = customSetter.empty()?"":", setter="+customSetter;
    std::string assigned = assignedType.empty()?"":", "+assignedType;
    std::stringstream ss;
    ss<<"@property("<<nonatomic<<assigned<<readOnly<<getter<<setter<<")"<<type<<" "<<name;
    std::string description = ss.str();
    
    if (this->name.compare("flowCellSize") == 0) {
        
        printf("\flowCellSize");
    }
    return description;
}

