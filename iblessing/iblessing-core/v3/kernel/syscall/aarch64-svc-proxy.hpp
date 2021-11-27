//
//  aarch64-svc-proxy.hpp
//  iblessing-core
//
//  Created by bxl on 2021/11/20.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef aarch64_svc_proxy_hpp
#define aarch64_svc_proxy_hpp

#include <stdio.h>
#include "aarch64-svc-manager.hpp"


NS_IB_BEGIN


class Aarch64SVCProxy : public Aarch64SVCManager {
public:
    Aarch64SVCProxy(uc_engine *uc, uint64_t addr, uint64_t size, int swiInitValue);
        
protected:
    virtual bool handleSyscall(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data);
        
};

NS_IB_END

#endif /* aarch64_svc_proxy_hpp */
