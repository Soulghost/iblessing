//
//  ScannerContext.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ScannerContext.hpp"
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <vector>

#include "VirtualMemory.hpp"
#include "VirtualMemoryV2.hpp"
#include "ObjcRuntime.hpp"
#include "StringTable.hpp"
#include "SymbolTable.hpp"

// FIXME: Cocoa Header
#include <mach-o/loader.h>
#include <mach-o/swap.h>

using namespace std;
using namespace iblessing;

#pragma mark - setup
scanner_err ScannerContext::setupWithBinaryPath(string binaryPath) {
    // mapping binary file
    cout << "[*] ScannerContext load binary file at " << binaryPath << endl;
    
    int fd = open(binaryPath.c_str(), O_RDWR);
    if (fd == -1) {
        return SC_ERR_INVALID_BINARY;
    }
    struct stat fileStatus;
    fstat(fd, &fileStatus);
    uint8_t *mappedFile = (uint8_t *)mmap(nullptr, fileStatus.st_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
    if (reinterpret_cast<int64_t>(mappedFile) == -1) {
        return SC_ERR_MAP_FAILED;
    }
    
    // read header
    struct mach_header_64 *hdr = (struct mach_header_64 *)mappedFile;
    uint32_t magic = hdr->magic;
    switch (magic) {
        case MH_MAGIC_64:
        case MH_CIGAM_64:
            cout << "[+] ScannerContext detect mach-o header 64" << endl;
            if (magic == MH_CIGAM_64) {
                cout << "[+] ScannerContext detect big-endian, swap header to litten-endian" << endl;
                swap_mach_header_64(hdr, NX_LittleEndian);
            } else {
                cout << "[+] ScannerContext detect litten-endian" << endl;
            }
            break;
        default: {
            return SC_ERR_UNSUPPORT_ARCH;
        }
    }
    
    // parse section headers
    // vmaddr base
    uint64_t vmaddr_base = 0;
    // symtab、dlsymtab、strtab's vmaddr base on LINKEDIT's vmaddr
    uint64_t linkedit_base = 0;
    uint64_t vmaddr_bss_start = 0;
    uint64_t vmaddr_bss_end = 0;
    
    uint32_t ncmds = hdr->ncmds;
    uint8_t *cmds = mappedFile + sizeof(struct mach_header_64);
    
    struct symtab_command *symtab_cmd = nullptr;
    struct dysymtab_command *dysymtab_cmd = nullptr;
    struct segment_command_64 *textSeg64 = nullptr;
    struct section_64 *textSect = nullptr;
    struct entry_point_command *mainSeg = nullptr;
    struct dyld_info_command *dyld_info = nullptr;
    uint64_t objc_classlist_addr = 0;
    uint64_t objc_classlist_size = 0;
    std::vector<struct section_64 *> sectionHeaders;
    std::vector<struct segment_command_64 *> segmentHeaders;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmds;
        switch (lc->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64 *seg64 = (struct segment_command_64 *)lc;
                segmentHeaders.push_back(seg64);
                if (strncmp(seg64->segname, "__TEXT", 6) == 0) {
                    textSeg64 = seg64;
                    vmaddr_base = seg64->vmaddr - seg64->fileoff;
                } else if (strncmp(seg64->segname, "__LINKEDIT", 10) == 0) {
                    linkedit_base = seg64->vmaddr - seg64->fileoff;
                }
                
                if (seg64->nsects > 0) {
                    struct section_64 *sect = (struct section_64 *)((uint8_t *)seg64 + sizeof(struct segment_command_64));
                    for (uint32_t i = 0; i < seg64->nsects; i++) {
                        // * Notice: sectname is char[16]
                        if (strncmp(sect->sectname, "__text", 16) == 0) {
                            textSect = sect;
                        }
                        if (strncmp(sect->sectname, "__bss", 16) == 0) {
                            vmaddr_bss_start = sect->addr;
                            vmaddr_bss_end = vmaddr_bss_start + sect->size;
                        }
                        if (strncmp(sect->sectname, "__objc_classlist", 16) == 0) {
                            objc_classlist_addr = sect->addr;
                            objc_classlist_size = sect->size;
                        }
                        sectionHeaders.push_back(sect);
                        sect += 1;
                    }
                }
                break;
            }
            case LC_MAIN: {
                struct entry_point_command *lc_main = (struct entry_point_command *)lc;
                mainSeg = lc_main;
                break;
            }
            case LC_SYMTAB: {
                symtab_cmd = (struct symtab_command *)lc;
                break;
            }
            case LC_DYSYMTAB: {
                dysymtab_cmd = (struct dysymtab_command *)lc;
                break;
            }
            case LC_DYLD_INFO_ONLY: {
                dyld_info = (struct dyld_info_command *)lc;
                break;
            }
            default:
                break;
        }
        cmds += lc->cmdsize;
    }
    
    VirtualMemory *vm = VirtualMemory::progressDefault();
    vm->vmaddr_base = vmaddr_base;
    vm->linkedit_base = linkedit_base;
    vm->vmaddr_bss_start = vmaddr_bss_start;
    vm->vmaddr_bss_end = vmaddr_bss_end;
    vm->mappedFile = mappedFile;
    vm->mappedSize = fileStatus.st_size;
    vm->segmentHeaders = segmentHeaders;
    vm->dyldinfo = dyld_info;
    vm->textSect = textSect;
    vm->textSeg = textSeg64;
    
    // load vm-v2
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    vm2->loadWithMachOData(mappedFile);
    
    ObjcRuntime *objcRuntime = ObjcRuntime::getInstance();
    objcRuntime->loadClassList(objc_classlist_addr, objc_classlist_size);

    // sort sectionHeaders by offset
    sort(sectionHeaders.begin(), sectionHeaders.end(), [&](struct section_64 *a, struct section_64 *b) {
        return a->offset < b->offset;
    });
    
    // test our searching
    if (!dyld_info) {
        return SC_ERR_MACHO_MISSING_SEGMENT_DYLD;
    }
    
    // sanity check
    if (!textSeg64) {
        return SC_ERR_MACHO_MISSING_SEGMENT_TEXT;
    }
    
    // build string table
    if (!symtab_cmd) {
        return SC_ERR_MACHO_MISSING_SEGMENT_SYMTAB;
    }
    if (!dysymtab_cmd) {
        return SC_ERR_MACHO_MISSING_SEGMENT_DYSYMTAB;
    }
    
    StringTable *strtab = StringTable::getInstance();
    uint64_t strtab_vmaddr = linkedit_base + symtab_cmd->stroff;
    strtab->buildStringTable(strtab_vmaddr, mappedFile + symtab_cmd->stroff, symtab_cmd->strsize);
    
    // symtab vmaddr will be loaded base on linkedit_base
    SymbolTable *symtab = SymbolTable::getInstance();
    symtab->buildSymbolTable(mappedFile + symtab_cmd->symoff, symtab_cmd->nsyms);
    symtab->buildDynamicSymbolTable(sectionHeaders, mappedFile + dysymtab_cmd->indirectsymoff, dysymtab_cmd->nindirectsyms, mappedFile);
    symtab->sync();
    
    return SC_ERR_OK;
}

#pragma mark - Getter
string ScannerContext::getBinaryPath() {
    return binaryPath;
}
