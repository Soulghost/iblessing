//
//  aarch64-svc-proxy.cpp
//  iblessing-core
//
//  Created by bxl on 2021/11/20.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "aarch64-svc-proxy.hpp"
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include "mach_traps.h"
#include "mach-universal.hpp"
#include "uc_debugger_utils.hpp"
#include "aarch64-machine.hpp"

using namespace std;
using namespace iblessing;

Aarch64SVCProxy::Aarch64SVCProxy(uc_engine *uc, uint64_t addr, uint64_t size, int swiInitValue, std::shared_ptr<MachOMemoryManager> mm) : Aarch64SVCManager(uc, addr, size, swiInitValue) {
    memoryManager = mm;
}

void getTrapNoAndArgs(uc_engine *uc, int *trap_no, uint64_t args[16]){
    assert(uc_reg_read(uc, UC_ARM64_REG_X16, trap_no) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X0, &args[0]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X1, &args[1]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X2, &args[2]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X3, &args[3]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X4, &args[4]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X5, &args[5]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X6, &args[6]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X7, &args[7]) == UC_ERR_OK);
    assert(uc_reg_read(uc, UC_ARM64_REG_X8, &args[8]) == UC_ERR_OK);

}

typedef kern_return_t   (*fptr_0)();
typedef kern_return_t   (*fptr_1)(uint64_t);
typedef kern_return_t   (*fptr_2)(uint64_t, uint64_t);
typedef kern_return_t   (*fptr_3)(uint64_t, uint64_t, uint64_t);
typedef kern_return_t   (*fptr_4)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef kern_return_t   (*fptr_5)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef kern_return_t   (*fptr_6)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef kern_return_t   (*fptr_7)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef kern_return_t   (*fptr_8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

bool Aarch64SVCProxy::handleNormalSyscall(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data){
    
    int trap_no = 0;
    int mach_trap_idx = 0;
    uint64_t args[16] = {0};
    getTrapNoAndArgs(uc, &trap_no, args);
    printf("[Stalker][+][Syscall] fallback to proxy syscall num %d: ", trap_no);
    if(trap_no > 0){
        printf(" \n");
        int ret = syscall(trap_no, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]);
        assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
        printf("\n");
        return true;
    }else{
        mach_trap_idx = -trap_no;
        int ret = 0;
        bool machMsg = false;
        if(mach_trap_idx >=0 && mach_trap_idx < MACH_TRAP_TABLE_COUNT){
            mach_trap_t trap = mach_trap_table[mach_trap_idx];
            printf(" %s", trap.mach_trap_name);
            if (trap_no == -31) {
                machMsg = true;
                ib_mach_msg_header_t *hdr = (ib_mach_msg_header_t *)args[0];
                printf("(msgh_id = %d(0x%x))\n", hdr->msgh_id, hdr->msgh_id);
            } else {
                printf("\n");
            }
            switch (trap.mach_trap_arg_count) {
                case 0:
                    ret = ((fptr_0)trap.mach_trap_function)(); break;
                case 1:
                    ret = ((fptr_1)trap.mach_trap_function)(args[0]); break;
                case 2:
                    ret = ((fptr_2)trap.mach_trap_function)(args[0], args[1]); break;
                case 3:
                    ret = ((fptr_3)trap.mach_trap_function)(args[0], args[1], args[2]); break;
                case 4:
                    ret = ((fptr_4)trap.mach_trap_function)(args[0], args[1], args[2], args[3]); break;
                case 5:
                    ret = ((fptr_5)trap.mach_trap_function)(args[0], args[1], args[2], args[3], args[4]); break;
                case 6:
                    ret = ((fptr_6)trap.mach_trap_function)(args[0], args[1], args[2], args[3], args[4], args[5]); break;
                case 7:
                    ret = ((fptr_7)trap.mach_trap_function)(args[0], args[1], args[2], args[3], args[4], args[5], args[6]); break;
                case 8:
                    ret = ((fptr_8)trap.mach_trap_function)(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]); break;
                default:
                    assert(false);
                    break;
            }
            if (machMsg && ret != 0) {
                ib_mach_msg_header_t *hdr = (ib_mach_msg_header_t *)args[0];
                mach_msg_header_t hh;
                ensure_uc_mem_read(args[0], &hh, sizeof(mach_msg_header_t));
                printf("[Stalker][!][Syscall][Error] mach_msg for id %d(0x%x) error: %s\n", hdr->msgh_id, hdr->msgh_id, mach_error_string(ret));
                uc_debug_print_backtrace(uc);
                int options = (int)args[1];
                if ((options & MACH_RCV_TIMEOUT) &&
                    (options & MACH_RCV_MSG) &&
                    (args[3] == 0x6C || args[3] == 0x7C) &&
                    ret == 0x10004003) {
                    printf("[Stalker][!][Syscall][Warn] allow timeout for this mach_msg\n");
                } else {
                    assert(false);
                }
            } else if (ret != 0) {
                // syscall / mach call
                if (trap_no == -70) {
                    uint64_t localargs[2];
                    ensure_uc_mem_read(args[1], localargs, 0x10);
                    printf("[Stalker][!][Syscall][Error] trap %d syscall/mach call error %s\n", trap_no, mach_error_string(ret));
                }
            }
            assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
            return true;
        }
         
    }
    return false;
}


bool Aarch64SVCProxy::handleSpecialSyscall(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data){
    int64_t trap_no = 0;
    assert(uc_reg_read(uc, UC_ARM64_REG_X16, &trap_no) == UC_ERR_OK);
    
    uint64_t cspr = 0;
    assert(uc_reg_read(uc, UC_ARM64_REG_NZCV, &cspr) == UC_ERR_OK);
    // clear carry
    cspr &= ~(1UL << 29);
    ensure_uc_reg_write(UC_ARM64_REG_NZCV, &cspr);
    // clear errno
    //machine.lock()->setErrno(0);
    
    if (trap_no > 0) {
        // posix
        switch (trap_no) {
            case 74: { // mprotect
                uint64_t addr, length;
                int prot;
                ensure_uc_reg_read(UC_ARM64_REG_X0, &addr);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &length);
                ensure_uc_reg_read(UC_ARM64_REG_W2, &prot);
                uint64_t alignedAddr = addr / 0x1000 * 0x1000;
                uint64_t offset = addr - alignedAddr;
                uint64_t alignedLength = IB_AlignSize(length + offset, 0x4000);
                uc_err err = uc_mem_protect(uc, alignedAddr, alignedLength, prot);
                assert(err == UC_ERR_OK);
                syscall_return_success;
                return true;
            }
            
            // sysctl
            case 202: {
                uint64_t nameAddr = 0;
                int nameLen = 0;
                assert(uc_reg_read(uc, UC_ARM64_REG_X0, &nameAddr) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_W1, &nameLen) == UC_ERR_OK);
                int name = 0;
                assert(uc_mem_read(uc, nameAddr, &name, sizeof(int)) == UC_ERR_OK);
                uint64_t bufferAddr = 0, bufferSizeAddr = 0;
                assert(uc_reg_read(uc, UC_ARM64_REG_X2, &bufferAddr) == UC_ERR_OK);
                assert(uc_reg_read(uc, UC_ARM64_REG_X3, &bufferSizeAddr) == UC_ERR_OK);
                switch (name) {
                    case 1: {// KERN
                        uint32_t action = 0;
                        assert(uc_mem_read(uc, nameAddr + 4, &action, sizeof(int)) == UC_ERR_OK);
                        switch (action) {
                            case 59: { // KERN_USRSTACK64
                                if (bufferSizeAddr != 0) {
                                    uint64_t bufferSize = 8;
                                    assert(uc_mem_write(uc, bufferSizeAddr, &bufferSize, sizeof(uint64_t)) == UC_ERR_OK);
                                }
                                if (bufferAddr != 0) {
                                    uint64_t stackBase = IB_STACK_START;
                                    assert(uc_mem_write(uc, bufferAddr, &stackBase, sizeof(uint64_t)) == UC_ERR_OK);
                                }
                                int ret = 0;
                                assert(uc_reg_write(uc, UC_ARM64_REG_W0, &ret) == UC_ERR_OK);
                                return true;
                            }
                        }
                        break;
                    }
                }
                break;
            }
            default:
                break;
        }
    } else if (trap_no < 0) {
        // mach
        int64_t call_number = -trap_no;
        
        switch (call_number) {
            case 10: { // _kernelrpc_mach_vm_allocate_trap
                int target, flags;
                uint64_t size, addrPtr;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &target);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &addrPtr);
                ensure_uc_reg_read(UC_ARM64_REG_X2, &size);
                ensure_uc_reg_read(UC_ARM64_REG_W3, &flags);
//                int tag = flags >> 24;
                assert(flags & IB_VM_FLAGS_ANYWHERE);
                uint64_t addr = memoryManager->alloc(size);
                void *zeros = calloc(1, size);
                uc_mem_write(uc, addr, zeros, size);
                free(zeros);
                ensure_uc_mem_write(addrPtr, &addr, sizeof(uint64_t));
                syscall_return_success;
                return true;
            }
            case 12: { // _kernelrpc_mach_vm_deallocate_trap
                // FIXME: mumap
                ib_mach_port_t target;
                uint64_t addr, size;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &target);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &addr);
                ensure_uc_reg_read(UC_ARM64_REG_X2, &size);
                printf("[Stalker][+][Mach] mach_vm_deallocate for task %d at 0x%llx, size 0x%llx\n", target, addr, size);
                memoryManager->dealloc(addr);
                syscall_return_success;
                return true;
            }
                
            case 15: { // _kernelrpc_mach_vm_map_trap
#if 0
                extern kern_return_t _kernelrpc_mach_vm_map_trap(
                    mach_port_name_t target,
                    mach_vm_offset_t *address,
                    mach_vm_size_t size,
                    mach_vm_offset_t mask,
                    int flags,
                    vm_prot_t cur_protection
                );
#endif
                ib_mach_port_t target;
                uint64_t addrPtr, size, mask;
                int flags, cur_prot;
                ensure_uc_reg_read(UC_ARM64_REG_W0, &target);
                ensure_uc_reg_read(UC_ARM64_REG_X1, &addrPtr);
                ensure_uc_reg_read(UC_ARM64_REG_X2, &size);
                ensure_uc_reg_read(UC_ARM64_REG_X3, &mask);
                ensure_uc_reg_read(UC_ARM64_REG_W4, &flags);
                ensure_uc_reg_read(UC_ARM64_REG_W5, &cur_prot);
                uint64_t addr;
                ensure_uc_mem_read(addrPtr, &addr, sizeof(uint64_t));
                // FIXME: mem mask
                uint64_t allocatedAddr = 0;
                allocatedAddr = (uint64_t)memoryManager->mmapSharedMem(0, size, cur_prot);
                //allocatedAddr = svc_uc_mmap(uc, 0, mask, size, cur_port, flags, -1, 0);
                
                assert(allocatedAddr != 0);
                // FIXME: tricky kern_mmap
                
                ensure_uc_mem_write(addrPtr, &allocatedAddr, sizeof(uint64_t));
                syscall_return_success;
                return true;
            }
                
            default:
                break;
        }
    }
    
    return false;
}

bool Aarch64SVCProxy::handleSyscall(uc_engine *uc, uint32_t intno, uint32_t swi, void *user_data) {
    shared_ptr<PthreadKern> threadManager = machine.lock()->threadManager;
    bool ret = Aarch64SVCManager::handleSyscall(uc, intno, swi, user_data);
    if (!ret) {
        ret = handleNormalSyscall(uc, intno, swi, user_data);
    }
    assert(ret == true);
    return ret;
}
