//
//  VirtualMemoryV2.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/3.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "VirtualMemoryV2.hpp"
#include "VirtualMemory.hpp"
#include "termcolor.h"
#include "StringUtils.h"
#include <vector>

using namespace std;
using namespace iblessing;

VirtualMemoryV2* VirtualMemoryV2::_instance = nullptr;

VirtualMemoryV2* VirtualMemoryV2::progressDefault() {
    if (VirtualMemoryV2::_instance == nullptr) {
        VirtualMemoryV2::_instance = new VirtualMemoryV2();
    }
    return VirtualMemoryV2::_instance;
}

int VirtualMemoryV2::loadWithMachOData(uint8_t *mappedFile) {
    // init unicorn
    if (this->uc) {
        return 1;
    }
    
    
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &this->uc);
    if (err) {
        printf("[-] unicorn error: %s\n", uc_strerror(err));
        return 1;
    }
    
    // mapping 12GB memory region, first 4GB is PAGEZERO
    uint64_t unicorn_vm_size = 12L * 1024 * 1024 * 1024;
    uint64_t unicorn_vm_start = 0;
    err = uc_mem_map(uc, unicorn_vm_start, unicorn_vm_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] Error: unicorn error: " << uc_strerror(err);
        cout << termcolor::reset << endl;
        exit(1);
    }
    
    // first of all, mapping the whole file
    VirtualMemory *vm = VirtualMemory::progressDefault();
    assert(uc_mem_write(uc, vm->vmaddr_base, mappedFile, vm->mappedSize) == UC_ERR_OK);
    
    // mapping file
    struct ib_mach_header_64 *hdr = (struct ib_mach_header_64 *)mappedFile;
    uint32_t magic = hdr->magic;
    switch (magic) {
        case IB_MH_MAGIC_64:
        case IB_MH_CIGAM_64:
//            cout << "[+] detect mach-o header 64" << endl;
            if (magic == IB_MH_CIGAM_64) {
//                cout << "[+] detect big-endian, swap header to litten-endian" << endl;
                ib_swap_mach_header_64(hdr, IB_LittleEndian);
            } else {
//                cout << "[+] detect litten-endian" << endl;
            }
            break;
        default: {
            cout << termcolor::red << "Error: unsupport arch, only support aarch64 now";
            cout << termcolor::reset << endl;
            break;
        }
    }
    
    // parse section headers
    // vmaddr base
    uint64_t vmaddr_base = 0;
    
    // symtab、dlsymtab、strtab's vmaddr base on LINKEDIT's vmaddr
    uint64_t linkedit_base = 0;
    uint64_t symoff = 0, symsize = 0;
    uint64_t stroff = 0, strsize = 0;
    
    uint32_t ncmds = hdr->ncmds;
    uint8_t *cmds = mappedFile + sizeof(struct ib_mach_header_64);
    
    struct ib_symtab_command *symtab_cmd = nullptr;
    struct ib_dysymtab_command *dysymtab_cmd = nullptr;
    struct ib_dyld_info_command *dyld_info = nullptr;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct ib_load_command *lc = (struct ib_load_command *)cmds;
        switch (lc->cmd) {
            case IB_LC_SEGMENT_64: {
                struct ib_segment_command_64 *seg64 = (struct ib_segment_command_64 *)lc;
                // FIXME: error condition
                uc_err err = uc_mem_write(uc, seg64->vmaddr, mappedFile + seg64->fileoff, std::min(seg64->vmsize, seg64->filesize));
                if (err != UC_ERR_OK) {
                    printf("[-] uc map failed reason: %s", uc_strerror(err));
                }
                
                if (strncmp(seg64->segname, "__TEXT", 6) == 0) {
                    vmaddr_base = seg64->vmaddr - seg64->fileoff;
                } else if (strncmp(seg64->segname, "__LINKEDIT", 10) == 0) {
                    linkedit_base = seg64->vmaddr - seg64->fileoff;
                }
                
                if (seg64->nsects > 0) {
                    struct ib_section_64 *sect = (struct ib_section_64 *)((uint8_t *)seg64 + sizeof(struct ib_segment_command_64));
                    for (uint32_t i = 0; i < seg64->nsects; i++) {
                        assert(uc_mem_write(uc, sect->addr, mappedFile + sect->offset, sect->size) == UC_ERR_OK);
//                        printf("[+] map section %s,%s 0x%llx - 0x%llx\n", seg64->segname, sect->sectname, sect->addr, sect->addr + sect->size);
                        sect += 1;
                    }
                }
                break;
            }
            case IB_LC_SYMTAB: {
                symtab_cmd = (struct ib_symtab_command *)lc;
                symoff = symtab_cmd->symoff;
                symsize = symtab_cmd->nsyms * sizeof(ib_nlist_64);
                stroff = symtab_cmd->stroff;
                strsize = symtab_cmd->strsize;
                break;
            }
            case IB_LC_DYSYMTAB: {
                dysymtab_cmd = (struct ib_dysymtab_command *)lc;
                break;
            }
            case IB_LC_DYLD_INFO_ONLY: {
                dyld_info = (struct ib_dyld_info_command *)lc;
                break;
            }
            default:
                break;
        }
        cmds += lc->cmdsize;
    }
    
    // map symtab & strtab
    assert(uc_mem_write(uc, linkedit_base + symoff, mappedFile + symoff, symsize) == UC_ERR_OK);
    assert(uc_mem_write(uc, linkedit_base + stroff, mappedFile + stroff, strsize) == UC_ERR_OK);
    
    return 0;
}

uint64_t VirtualMemoryV2::read64(uint64_t address, bool *success) {
    uint64_t bytes = 0;
    if (uc_mem_read(uc, address, &bytes, 8) == UC_ERR_OK) {
        if (success) {
            *success = true;
        }
        return bytes;
    }
    
    if (success) {
        *success = false;
    }
    return 0;
}

void* VirtualMemoryV2::readBySize(uint64_t address, uint64_t size) {
    void *buffer = malloc(size);
    if (uc_mem_read(uc, address, buffer, size) == UC_ERR_OK) {
        return buffer;
    }
    
    free(buffer);
    return nullptr;
}

uint32_t VirtualMemoryV2::read32(uint64_t address, bool *success) {
    uint32_t bytes = 0;
    if (uc_mem_read(uc, address, &bytes, 4) == UC_ERR_OK) {
        if (success) {
            *success = true;
        }
        return bytes;
    }
    
    if (success) {
        *success = false;
    }
    return 0;
}

char* VirtualMemoryV2::readString(uint64_t address, uint64_t limit) {
    char *charBuf = (char *)malloc(limit + 1);
    uint64_t offset = 0;
    uint64_t unPrintCount = 0;
    bool ok = true;
    while (offset < limit && (ok = (uc_mem_read(uc, address + offset, charBuf + offset, sizeof(char))) == UC_ERR_OK)) {
        if (charBuf[offset] == 0) {
            break;
        }
        if (!(charBuf[offset] >= 0x20 && charBuf[offset] <= 0x7E)) {
            unPrintCount++;
            if (unPrintCount > 10) {
                ok = false;
                break;
            }
        }
        offset++;
    }
    
    if (!ok) {
        free(charBuf);
        return NULL;
    }
    
    charBuf[offset] = 0;
    char *strBuffer = (char *)malloc(offset + 1);
    memcpy(strBuffer, charBuf, offset + 1);
    free(charBuf);
    return strBuffer;
}

CFString* VirtualMemoryV2::readAsCFString(uint64_t address, bool needCheck) {
    CFString *str = (CFString *)malloc(sizeof(CFString));
    uc_err err = uc_mem_read(uc, address, str, sizeof(CFString));
    if (err != UC_ERR_OK) {
        free(str);
        return nullptr;
    }
    
    // FIXME: the best check is compare by isa ___CFConstantStringClassReference
    if (needCheck) {
        // simple check
        if (str->length == 0 || str->length > 1000) {
            free(str);
            return nullptr;
        }
        
        int checkLen = std::min((int)str->length, 10);
        char *tmpBuf = (char *)malloc(checkLen);
        err = uc_mem_read(uc, str->data, tmpBuf, checkLen);
        if (err != UC_ERR_OK) {
            free(str);
            free(tmpBuf);
            return nullptr;
        }
        
        if (StringUtils::countNonPrintablecharacters(tmpBuf, 10) > 5) {
            // too many non-printable chars, the str maybe invalid
            free(str);
            free(tmpBuf);
            return nullptr;
        }
    }
    
    return str;
}

char* VirtualMemoryV2::readAsCFStringContent(uint64_t address, bool needCheck) {
    CFString *cfstr = readAsCFString(address, needCheck);
    if (!cfstr) {
        return nullptr;
    }
    
    char *content = (char *)malloc(cfstr->length + 1);
    content[cfstr->length] = 0;
    uc_err err = uc_mem_read(uc, cfstr->data, content, cfstr->length);
    if (err != UC_ERR_OK) {
        free(content);
        free(cfstr);
        return nullptr;
    }
    free(cfstr);
    return content;
}
