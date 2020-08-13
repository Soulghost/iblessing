//
//  CoreFoundation.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/13.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef CoreFoundation_hpp
#define CoreFoundation_hpp

#include "Object.hpp"
#include <vector>

NS_IB_BEGIN

class CoreFoundation {
public:
    static std::vector<std::string> argumentsFromSignature(const char *signaure);
};

NS_IB_END

#endif /* CoreFoundation_hpp */
