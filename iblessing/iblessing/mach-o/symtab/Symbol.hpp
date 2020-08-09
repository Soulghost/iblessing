//
//  Symbol.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef Symbol_hpp
#define Symbol_hpp

#include "Object.hpp"
#include "mach-universal.hpp"

NS_IB_BEGIN

class Symbol : public Object {
public:
    Symbol();
    virtual ~Symbol();
    
    std::string name;
    struct ib_nlist_64 *info;
};

NS_IB_END

#endif /* Symbol_hpp */
