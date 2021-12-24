//
//  mach-ipc-manager.hpp
//  mach-ipc-manager
//
//  Created by Soulghost on 2021/12/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef mach_ipc_manager_hpp
#define mach_ipc_manager_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/core/polyfill/mach-universal.hpp>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v3/fs/darwin-file-system.hpp>
#include <map>

NS_IB_BEGIN

class Aarch64Machine;

enum MachIPCPortType {
    MachIPCPortTypePort = 0,
    MachIPCPortTypeVoucherPort
};

class MachIPCPort {
public:
    MachIPCPort();
    
    MachIPCPortType type;
    ib_mach_port_t name;
};

class MachVoucherPort : public MachIPCPort {
public:
    MachVoucherPort();
};

class MachIPCManager {
public:
    MachIPCManager(std::weak_ptr<Aarch64Machine> machine);
    
    ib_return_t host_create_mach_voucher(ib_mach_port_t host_port, uint64_t recipesAddr, int recipeSize, uint64_t new_voucher_addr);
    
protected:
    std::weak_ptr<Aarch64Machine> machine;
    uc_engine *uc;
    ib_mach_port_t portCounter;
    
    std::map<ib_mach_port_t, std::shared_ptr<MachIPCPort>> portMap;
    
    ib_mach_port_t allocatePortIndex();
    void insertPort(std::shared_ptr<MachIPCPort> port);
};

NS_IB_END

#endif /* mach_ipc_manager_hpp */
