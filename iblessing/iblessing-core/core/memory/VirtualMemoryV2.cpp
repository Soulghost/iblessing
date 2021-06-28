//
//  VirtualMemoryV2.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/3.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "VirtualMemoryV2.hpp"
#include "VirtualMemory.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include "mach-machine.h"
#include "ScannerContext.hpp"
#include "SymbolTable.hpp"
#include "ObjcRuntime.hpp"

using namespace std;
using namespace iblessing;

VirtualMemoryV2* VirtualMemoryV2::_instance = nullptr;

VirtualMemoryV2* VirtualMemoryV2::progressDefault() {
    if (VirtualMemoryV2::_instance == nullptr) {
        VirtualMemoryV2::_instance = nullptr;
    }
    return VirtualMemoryV2::_instance;
}

uint8_t* VirtualMemoryV2::getMappedFile() {
    return fileMemory->mappedFile;
}

uint64_t VirtualMemoryV2::getBaseAddr() {
    return fileMemory->vmaddr_base;
}

std::vector<struct ib_segment_command_64 *> VirtualMemoryV2::getSegmentHeaders() {
    return fileMemory->segmentHeaders;
}

struct ib_section_64* VirtualMemoryV2::getTextSect() {
    return fileMemory->textSect;
}

struct ib_dyld_info_command* VirtualMemoryV2::getDyldInfo() {
    return fileMemory->dyldinfo;
}

int VirtualMemoryV2::loadWithMachOData(shared_ptr<SymbolTable> symtab, shared_ptr<ObjcRuntime> objcRuntime, uint8_t *mappedFile) {
    // init unicorn
    if (this->uc) {
        return 1;
    }
    
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &this->uc);
    if (err) {
        printf("[-] unicorn error: %s\n", uc_strerror(err));
        return 1;
    }
    
    return mappingMachOToEngine(symtab, objcRuntime, uc, mappedFile);
}

int VirtualMemoryV2::mappingMachOToEngine(shared_ptr<SymbolTable> symtab, shared_ptr<ObjcRuntime> objcRuntime, uc_engine *uc, uint8_t *mappedFile) {
    if (!uc) {
        return 1;
    }
    
    // mach-o mapping start from 0x100000000 (app), 0x0 (dylib)
    // heap using vm_base ~ vmbase + 12G
    // stack using vmbase + 12G ~ .
    uint64_t unicorn_vm_size = 12UL * 1024 * 1024 * 1024;
    uint64_t unicorn_vm_start = fileMemory->vmaddr_base;
    uc_err err = uc_mem_map(uc, unicorn_vm_start, unicorn_vm_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] VirtualMemoryV2 - Error: unicorn error: " << uc_strerror(err);
        cout << termcolor::reset << endl;
        return 2;
    }
    
    // first of all, mapping the whole file
    err = uc_mem_write(uc, fileMemory->vmaddr_base, mappedFile, fileMemory->mappedSize);
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] VirtualMemoryV2 - Error: cannot map mach-o file: " << uc_strerror(err);
        cout << termcolor::reset << endl;
        return 3;
    }
    
    // mapping file
    struct ib_mach_header_64 *hdr = nullptr;
    if (ScannerContext::headerDetector(mappedFile, &hdr) != SC_ERR_OK) {
        cout << termcolor::red << "[-] VirtualMemoryV2 - cannot extract aarch64 header from binary file";;
        cout << termcolor::reset << endl;
        return 4;
    }
    
    // parse section headers
    // vmaddr base
    uint64_t vmaddr_base = 0;
    vector<pair<uint64_t, uint64_t>> textSects;
    
    // symtab、dlsymtab、strtab's vmaddr base on LINKEDIT's vmaddr
    uint64_t linkedit_base = 0;
    uint64_t symoff = 0, symsize = 0;
    uint64_t stroff = 0, strsize = 0;
    uint32_t ncmds = hdr->ncmds;
    uint8_t *cmds = mappedFile + sizeof(struct ib_mach_header_64);
    for (uint32_t i = 0; i < ncmds; i++) {
        struct ib_load_command *lc = (struct ib_load_command *)cmds;
        switch (lc->cmd) {
            case IB_LC_SEGMENT_64: {
                struct ib_segment_command_64 *seg64 = (struct ib_segment_command_64 *)lc;
                uc_err err = uc_mem_write(uc, seg64->vmaddr, mappedFile + seg64->fileoff, std::min(seg64->vmsize, seg64->filesize));
                if (err != UC_ERR_OK) {
                    cout << termcolor::red << "[-] VirtualMemoryV2 - Error: cannot map segment ";
                    cout << termcolor::red << StringUtils::format("%s(0x%llx~0x%llx)",
                                                                  seg64->segname,
                                                                  seg64->vmaddr,
                                                                  seg64->vmaddr + std::min(seg64->vmsize, seg64->filesize));
                    cout << ", error " << uc_strerror(err);
                    cout << termcolor::reset << endl;
                    return 5;
                }
                
                if (strncmp(seg64->segname, "__TEXT", 6) == 0) {
                    vmaddr_base = seg64->vmaddr - seg64->fileoff;
                } else if (strncmp(seg64->segname, "__LINKEDIT", 10) == 0) {
                    linkedit_base = seg64->vmaddr - seg64->fileoff;
                }
                
                if (seg64->nsects > 0) {
                    struct ib_section_64 *sect = (struct ib_section_64 *)((uint8_t *)seg64 + sizeof(struct ib_segment_command_64));
                    for (uint32_t i = 0; i < seg64->nsects; i++) {
                        char *sectname = (char *)malloc(16);
                        memcpy(sectname, sect->sectname, 16);
                        addr2segInfo[sect->addr] = {string(sect->segname), string(sectname)};
                        free(sectname);
                        if (strcmp(sect->sectname, "__text") == 0) {
                            textSects.push_back({sect->addr, sect->size});
                        }
                        uc_err err = uc_mem_write(uc, sect->addr, mappedFile + sect->offset, sect->size);
                        if (err != UC_ERR_OK) {
                            cout << termcolor::red << "[-] VirtualMemoryV2 - Error: cannot map section ";
                            cout << StringUtils::format("%s(0x%llx~0x%llx)",
                                                        sect->segname,
                                                        sect->addr,
                                                        sect->addr + sect->size);
                            cout << ", error " << uc_strerror(err);
                            cout << termcolor::reset << endl;
                        }
//                        printf("[+] map section %s,%s 0x%llx - 0x%llx\n", seg64->segname, sect->sectname, sect->addr, sect->addr + sect->size);
                        sect += 1;
                    }
                }
                break;
            }
            case IB_LC_SYMTAB: {
                struct ib_symtab_command *symtab_cmd = (struct ib_symtab_command *)lc;
                symoff = symtab_cmd->symoff;
                symsize = symtab_cmd->nsyms * sizeof(ib_nlist_64);
                stroff = symtab_cmd->stroff;
                strsize = symtab_cmd->strsize;
                break;
            }
            default:
                break;
        }
        cmds += lc->cmdsize;
    }
    
    // map symtab & strtab
    err = uc_mem_write(uc, linkedit_base + symoff, mappedFile + symoff, symsize);
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] VirtualMemoryV2 - Error: cannot map symbol table: " << uc_strerror(err);
        cout << termcolor::reset << endl;
        return 1;
    }
    
    err = uc_mem_write(uc, linkedit_base + stroff, mappedFile + stroff, strsize);
    if (err != UC_ERR_OK) {
        cout << termcolor::red << "[-] VirtualMemoryV2 - Error: cannot map string table: " << uc_strerror(err);
        cout << termcolor::reset << endl;
        return 1;
    }
    
    if (uc != this->uc) {
        // sync text segment since we may have fixed it
        for (pair<uint64_t, uint32_t> patch : textPatch) {
            uc_mem_write(uc, patch.first, &patch.second, sizeof(uint32_t));
        }
        relocAllRegions(symtab, objcRuntime, uc);
    }
    return 0;
}

void VirtualMemoryV2::relocAllRegions(shared_ptr<SymbolTable> symtab, shared_ptr<ObjcRuntime> objcRuntime, uc_engine *target) {
    if (target == nullptr) {
        target = this->uc;
    }
    // perform relocs
    for (SymbolRelocation &reloc : symtab->getAllRelocs()) {
        string relocSection = string(reloc.relocSection->sectname, std::min((int)strlen(reloc.relocSection->sectname), 16));
        if (relocSection == "__text") {
            // skip text reloc
            continue;
        }
        
        if (relocSection == "__objc_classrefs") {
            Symbol *symbol = reloc.relocSymbol;
            string symbolName = symbol->name;
            if (symbolName.rfind("_OBJC_CLASS_$") == 0) {
                ObjcClassRuntimeInfo *externalClassInfo = new ObjcClassRuntimeInfo();
                externalClassInfo->isExternal = true;
                
                vector<string> parts = StringUtils::split(symbolName, '_');
                if (parts.size() > 1) {
                    externalClassInfo->className = parts[parts.size() - 1];
                } else {
                    externalClassInfo->className = symbolName;
                }
                objcRuntime->externalClassRuntimeInfo[reloc.relocAddr] = externalClassInfo;
                objcRuntime->name2ExternalClassRuntimeInfo[externalClassInfo->className] = externalClassInfo;
                objcRuntime->runtimeInfo2address[externalClassInfo] = reloc.relocAddr;
                uc_mem_write(target, reloc.relocAddr, &reloc.relocAddr, 8);
            }
        } else {
            uint64_t originAddr = reloc.relocAddr;
            uint64_t relocAddr = reloc.relocValue;
            uint64_t relocSize = reloc.relocSize;
            uc_mem_write(target, originAddr, &relocAddr, relocSize);
        }
    }
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

bool VirtualMemoryV2::write32(uint64_t address, uint32_t value) {
    return uc_mem_write(uc, address, &value, 4) == UC_ERR_OK;
}

bool VirtualMemoryV2::write64(uint64_t address, uint64_t value) {
    return uc_mem_write(uc, address, &value, 8) == UC_ERR_OK;
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

uc_engine* VirtualMemoryV2::getEngine() {
    return this->uc;
}

pair<std::string, std::string> VirtualMemoryV2::querySegInfo(uint64_t address) {
    auto it = addr2segInfo.lower_bound(address);
    if (it->first == address) {
        return it->second;
    }
    return (--it)->second;
}
