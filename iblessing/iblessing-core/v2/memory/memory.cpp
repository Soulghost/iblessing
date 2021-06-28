//
//  memory.cpp
//  iblessing
//
//  Created by soulghost on 2021/4/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "memory.hpp"
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/objc/objc.hpp>
#include <iblessing-core/v2/vendor/keystone/keystone.h>
#include <iblessing-core/v2/vendor/capstone/capstone.h>

using namespace std;
using namespace iblessing;

shared_ptr<Memory> Memory::createFromMachO(shared_ptr<MachO> macho) {
    shared_ptr<Memory> mem = make_shared<Memory>(macho);
    return mem;
}

ib_return_t Memory::loadSync() {
    if (!macho) {
        return IB_MEMORY_LOAD_ERROR_INVALID_MACHO;
    }
    
    // load vm-v2
    shared_ptr<VirtualMemory> vm = macho->context->fileMemory;
    shared_ptr<VirtualMemoryV2> vm2 = make_shared<VirtualMemoryV2>(vm);
    this->fileMemory = vm;
    this->virtualMemory = vm2;
    
    int code = vm2->loadWithMachOData(macho->context->symtab, macho->context->objcRuntime, vm->mappedFile);
    if (code != 0) {
        return IB_MEMORY_MAPPING_ERROR;
    }
    
    // reloc text region
    uint64_t textStart = vm->textSect->addr;
    uint64_t textEnd = textStart + vm->textSect->size;
    auto &allRelocs = vm->allRelocs;
    if (allRelocs.size() > 0) {
        ks_engine *ks;
        assert(ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks) == KS_ERR_OK);
        
        csh handle;
        assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        
        for (pair<pair<uint64_t, uint64_t>, pair<uint64_t, ib_section_64 *>> &reloc : allRelocs) {
            uint64_t relocInfoAddr = reloc.first.first;
            uint64_t relocInfoCount = reloc.first.second;
            uint64_t relocInfoBase = reloc.second.first;
            ib_section_64 *relocSection = reloc.second.second;
            
            struct ib_scattered_relocation_info *reloc_info = (struct ib_scattered_relocation_info *)(vm->mappedFile + relocInfoAddr);
            while (relocInfoCount--) {
                uint64_t targetAddr = relocInfoBase + (reloc_info->r_address & 0x00ffffff);
                uint64_t symbolNum = (reloc_info->r_value & 0x00ffffff);
                macho->context->symtab->relocSymbol(targetAddr, symbolNum, relocSection);
                reloc_info++;
                
                if (targetAddr >= textStart && targetAddr <= textEnd) {
                    uint64_t insnAddr = targetAddr;
                    cs_insn *insn = nullptr;
                    uint32_t asmcode = vm2->read32(targetAddr, nullptr);
                    uint8_t *code = (uint8_t *)&asmcode;
                    size_t count = cs_disasm(handle, code, 4, insnAddr, 0, &insn);
                    if (count == 1) {
                        bool needFix = false;
                        size_t size = 0, count = 0;
                        unsigned char *encode = nullptr;
                        if (strcmp(insn->mnemonic, "adrp") == 0) {
                            string text = StringUtils::format("%s %s", insn->mnemonic, insn->op_str);
                            uint64_t relocPage = macho->context->symtab->relocQuery(targetAddr);
                            uint64_t page = (relocPage & ~0xfff);
                            string fixup = StringUtils::split(text, '#')[0];
                            fixup += StringUtils::format("0x%llx", page);
                            if (ks_asm(ks, fixup.c_str(), targetAddr, &encode, &size, &count) == KS_ERR_OK) {
                                needFix = true;
                            };
                        } else if (strcmp(insn->mnemonic, "ldr") == 0) {
                            string text = StringUtils::format("%s %s", insn->mnemonic, insn->op_str);
                            uint64_t relocPage = macho->context->symtab->relocQuery(targetAddr);
                            uint64_t pageoff = relocPage & 0xfff;
                            string fixup = StringUtils::split(text, ']')[0];
                            fixup += StringUtils::format(", #0x%llx]", pageoff);
                            if (ks_asm(ks, fixup.c_str(), targetAddr, &encode, &size, &count) == KS_ERR_OK) {
                                needFix = true;
                            };
                        } else if (strcmp(insn->mnemonic, "add") == 0) {
                            string text = StringUtils::format("%s %s", insn->mnemonic, insn->op_str);
                            uint64_t relocPage = macho->context->symtab->relocQuery(targetAddr);
                            uint64_t pageoff = relocPage & 0xfff;
                            vector<string> parts = StringUtils::split(text, ',');
                            string fixup = parts[0] + ", " + parts[1];
                            fixup += StringUtils::format(", #0x%llx", pageoff);
                            if (ks_asm(ks, fixup.c_str(), targetAddr, &encode, &size, &count) == KS_ERR_OK) {
                                needFix = true;
                            };
                        }
                        
                        if (needFix) {
                            uint32_t fixcode = 0;
                            for (size_t i = 0; i < size; i++) {
                                fixcode += (encode[i] << (i * 8));
                            }
                            vm2->write32(targetAddr, fixcode);
                            vm2->textPatch.push_back({targetAddr, fixcode});
                        }
                    }
                }
            }
        }
    }
    macho->context->symtab->sync();
    
    shared_ptr<Objc> objc = Objc::create(macho, this);
    this->objc = objc;
    macho->context->objcRuntime = objc->getRuntime();
    vm2->relocAllRegions(macho->context->symtab, macho->context->objcRuntime);
    return IB_SUCCESS;
}

ib_return_t Memory::copyToUCEngine(uc_engine *uc) {
    if (!uc) {
        return IB_INVALID_ARGUMENTS;
    }
    
    if (!this->virtualMemory) {
        return IB_UNINIT_MODULE;
    }
    
    shared_ptr<VirtualMemoryV2> vm2 = this->virtualMemory;
    int ret = vm2->mappingMachOToEngine(macho->context->symtab, macho->context->objcRuntime, uc, this->fileMemory->mappedFile);
    if (ret == 0) {
        return IB_SUCCESS;
    } else {
        return IB_MEMORY_COPYOUT_ERROR;
    }
}
