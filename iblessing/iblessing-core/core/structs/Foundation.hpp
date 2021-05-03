//
//  Foundation.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/26.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef Foundation_hpp
#define Foundation_hpp

#include <iblessing-core/infra/Object.hpp>

NS_IB_BEGIN

typedef struct CFString {
    uint64_t isa;
    uint64_t info;
    uint64_t data;
    uint64_t length;
} CFString __attribute__((aligned(8)));

NS_IB_END

#endif /* Foundation_hpp */
