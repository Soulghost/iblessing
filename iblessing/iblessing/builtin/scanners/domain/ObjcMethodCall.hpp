//
//  ObjcMethodCall.hpp
//  iblessing
//
//  Created by Soulghost on 2020/10/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcMethodCall_hpp
#define ObjcMethodCall_hpp

#include "ObjcMethod.hpp"

NS_IB_BEGIN

class ObjcMethodCallArg {
public:
    std::string typeEncoding;
    std::string typeName;
    std::string value;
    bool isPrimaryType;
    bool resolved;
    
    ObjcMethodCallArg(std::string typeEncoding, std::string typeName, std::string value, bool isPrimaryType, bool resolved) {
        this->typeEncoding = typeEncoding;
        this->typeName = typeName;
        this->value = value;
        this->isPrimaryType = isPrimaryType;
        this->resolved = resolved;
    }
    
    bool operator < (const ObjcMethodCallArg &rhs) const {
        if (typeName < rhs.typeName) {
            return true;
        } else if (typeName > rhs.typeName) {
            return false;
        }
        return value < rhs.value;
    }
};

class ObjcMethodCall {
public:
    ObjcMethod *method;
    std::vector<ObjcMethodCallArg> args;
    
    ObjcMethodCall(ObjcMethod *method, std::vector<ObjcMethodCallArg> &args) {
        this->method = method;
        this->args = args;
    }
    
    bool operator < (const ObjcMethodCall &rhs) const {
        return args < rhs.args;
    }
};

NS_IB_END

#endif /* ObjcMethodCall_hpp */
