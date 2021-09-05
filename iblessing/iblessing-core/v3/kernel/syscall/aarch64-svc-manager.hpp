//
//  aarch64-svc-manager.hpp
//  iblessing-core
//
//  Created by Soulghost on 2021/9/4.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef aarch64_svc_manager_hpp
#define aarch64_svc_manager_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <map>

NS_IB_BEGIN

typedef std::function<void (uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data)> Aarch64SVCCallback;

struct Aarch64SVC {
    int swi;
    Aarch64SVCCallback callback;
};

class Aarch64SVCManager {
public:
    Aarch64SVCManager(uc_engine *uc, uint64_t addr, uint64_t size, int swiInitValue);
    
    uint64_t createSVC(int swi, Aarch64SVCCallback callback);
    uint64_t createSVC(Aarch64SVCCallback callback);
    bool handleSVC(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data);
    
protected:
    uint64_t addr;
    uint64_t curAddr;
    uint64_t size;
    uc_engine *uc;
    int swiGenerator;
    std::map<int, Aarch64SVC> svcMap;
};

NS_IB_END

#endif /* aarch64_svc_manager_hpp */