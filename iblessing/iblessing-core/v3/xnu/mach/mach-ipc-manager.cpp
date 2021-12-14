//
//  mach-ipc-manager.cpp
//  mach-ipc-manager
//
//  Created by Soulghost on 2021/12/14.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "mach-ipc-manager.hpp"
#include "aarch64-machine.hpp"
#include "uc_debugger_utils.hpp"

using namespace std;
using namespace iblessing;

#pragma mark - MachIPCPort
MachIPCPort::MachIPCPort() {
    this->type = MachIPCPortTypePort;
}

#pragma mark - MachVoucherPort
MachVoucherPort::MachVoucherPort() {
    this->type = MachIPCPortTypeVoucherPort;
}

MachIPCManager::MachIPCManager(std::weak_ptr<Aarch64Machine> machine) {
    this->machine = machine;
    this->uc = machine.lock()->uc;
    portCounter = 10086;
}

ib_return_t MachIPCManager::host_create_mach_voucher(ib_mach_port_t host_port, uint64_t recipesAddr, int recipeSize, uint64_t new_voucher_addr) {
    ib_mach_port_t voucher_port = allocatePortIndex();
    
    shared_ptr<MachVoucherPort> voucherPort = make_shared<MachVoucherPort>();
    voucherPort->name = voucher_port;
    insertPort(voucherPort);
    
    // IPC FIXME: handle recipes
    
    uc_debug_print_backtrace(uc);
    ensure_uc_mem_write(new_voucher_addr, &voucher_port, sizeof(ib_mach_port_t));
    return 0;
}

ib_mach_port_t MachIPCManager::allocatePortIndex() {
    return portCounter++;
}

void MachIPCManager::insertPort(shared_ptr<MachIPCPort> port) {
    portMap[port->name] = port;
}
