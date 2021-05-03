//
//  CommonDefines.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef CommonDefines_hpp
#define CommonDefines_hpp

#define NS_IB_BEGIN namespace iblessing {
#define NS_IB_END }
#define CCASSERT(cond, desc) IBASSERT(cond, desc)
#define IBASSERT(cond, desc) assert(cond)

#endif /* CommonDefines_hpp */
