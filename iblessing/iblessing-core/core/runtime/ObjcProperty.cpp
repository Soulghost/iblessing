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
    if (StringUtils::has_prefix(typeString, "T")) {
        typeString = typeString.substr(1);//移除T
    }
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
//            assignedType = "weak";
            type = "__weak "+type;
        }
    }
}

std::string ObjcProperty::getTypeWithTypeSign(std::string typeSign) {
    
    std::string type;
    if (StringUtils::has_prefix(typeSign, "B")) {
        type = "_Bool ";
    } else if (StringUtils::has_prefix(typeSign, "c")) {
        type = "char ";
    } else if (StringUtils::has_prefix(typeSign, "C")) {
        type = "unsigned char ";
    } else if (StringUtils::has_prefix(typeSign, "d")) {
        type = "double ";
    } else if (StringUtils::has_prefix(typeSign, "i")) {
        type = "int ";
    } else if (StringUtils::has_prefix(typeSign, "I")) {
        type = "unsigned int ";
    } else if (StringUtils::has_prefix(typeSign, "f")) {
        type = "float ";
    } else if (StringUtils::has_prefix(typeSign, "l")) {
        type = "long ";
    } else if (StringUtils::has_prefix(typeSign, "s")) {
        type = "short ";
    } else if (StringUtils::has_prefix(typeSign, "q")) {
        type = "long long ";
    } else if (StringUtils::has_prefix(typeSign, "Q")) {
        type = "unsigned long long ";
    } else if (StringUtils::has_prefix(typeSign, "#")) {
        type = "Class ";
    } else if (StringUtils::has_prefix(typeSign, ":")) {
        type = "SEL ";
    } else if (StringUtils::has_prefix(typeSign, "r*")) {
        type = "const char *";
    } else if (StringUtils::has_prefix(typeSign, "@\"")) {
        std::size_t front = typeSign.find("@\"");
        std::size_t back = typeSign.rfind("\"", typeSign.length());
        type = typeSign.substr(front+2, back-2)+" *";
    } else if (StringUtils::has_prefix(typeSign, "@")) {
        type = "id ";
    } else if (StringUtils::has_prefix(typeSign, "{")) {//struct
        type = this->handleStructWithTypeSign(typeSign);
    } else if (StringUtils::has_prefix(typeSign, "^{")) {//block
        type = this->handleStructWithTypeSign(typeSign);
    }
    return type;
}

std::string ObjcProperty::handleStructWithTypeSign(std::string typeSign) {
    if (StringUtils::has_prefix(typeSign, "{") && typeSign.length() == 1) {
        
        return "";
    }
    if (StringUtils::has_prefix(typeSign, "{")) {//struct
        size_t structNameIndex = typeSign.find("{");
        size_t structTypeIndex = typeSign.find("=");
        std::string structName = typeSign.substr(structNameIndex+1, structTypeIndex-2);
        std::string structType = typeSign.substr(structTypeIndex+1);
        type = "struct{";
        for (auto i = structType.begin(); i<=structType.end()-2; i++) {
            std::string s = StringUtils::format("%c",*i);
            std::string subType = getTypeWithTypeSign(s);
//            type += StringUtils::format("%s = %s%ld;", s.c_str(), s.c_str(), i-structType.begin());
            type += StringUtils::format("%s%s%ld;", subType.c_str(), subType.substr(0, subType.length()-1).c_str(), i-structType.begin());
        }
        type += "}";
        printf("end");
    } else if (typeSign.find("^{") != std::string::npos) {//block
        type = "id";
    }
    return type;
}

std::string ObjcProperty::description() {
    
    std::string nonatomic = isNonatomic?"nonatomic":"atomic";
    std::string readOnly = isReadOnly?", readonly":"";
    std::string getter = customGetter.empty()?"":", getter="+customGetter;
    std::string setter = customSetter.empty()?"":", setter="+customSetter;
    std::string assigned = assignedType.empty()?"":", "+assignedType;
    std::stringstream ss;
    ss<<"@property("<<nonatomic<<assigned<<readOnly<<getter<<setter<<")"<<type<<name;
    std::string description = ss.str();
    
    if (this->name.compare("flowCellSize") == 0) {
        
        printf("\flowCellSize");
    }
    return description;
}

