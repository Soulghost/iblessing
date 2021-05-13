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
    
    /*
     @property (readonly) NSString *name;
     @property (readonly) NSString *attributeString;
     @property (readonly) CDType *type;
     @property (readonly) NSArray *attributes;

     @property (strong) NSString *attributeStringAfterType;

     @property (nonatomic, readonly) NSString *defaultGetter;
     @property (nonatomic, readonly) NSString *defaultSetter;

     @property (strong) NSString *customGetter;
     @property (strong) NSString *customSetter;

     @property (nonatomic, readonly) NSString *getter;
     @property (nonatomic, readonly) NSString *setter;

     @property (readonly) BOOL isReadOnly;
     @property (readonly) BOOL isDynamic;

     **/
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
    
    bool isReadOnly;
    bool isDynamic;
    
    ObjcProperty(struct ib_property_t property);
    std::string getter();
    std::string setter();
private:
    void handleAttributeString();
};
NS_IB_END
#endif /* ObjcProperty_hpp */
