//
//  pthread_kern.hpp
//  pthread_kern
//
//  Created by Soulghost on 2022/1/8.
//  Copyright © 2022 soulghost. All rights reserved.
//

#ifndef pthread_kern_hpp
#define pthread_kern_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
//#include <iblessing-core/v3/mach-o/macho-loader.hpp>
//#include <iblessing-core/v3/kernel/syscall/aarch64-svc-manager.hpp>

NS_IB_BEGIN

class PthreadKern {
public:
    uint64_t proc_threadstart;
    uint64_t proc_wqthread;
};

NS_IB_END

#endif /* pthread_kern_hpp */
