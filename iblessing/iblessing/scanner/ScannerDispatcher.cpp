//
//  ScannerDispatcher.cpp
//  iblessing
//
//  Created by soulghost on 2020/6/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ScannerDispatcher.hpp"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <set>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>
#include <sys/mman.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/swap.h>
#include <architecture/byte_order.h>

#include "termcolor.h"
#include "StringUtils.h"
#include <capstone/capstone.h>
#include "SymbolTable.hpp"
#include "StringTable.hpp"
#include "ARM64Registers.hpp"
#include "ARM64Disasembler.hpp"
#include "VirtualMemory.hpp"
#include "VirtualMemoryV2.hpp"
#include "ARM64Runtime.hpp"
#include "ARM64ThreadState.hpp"
#include "ObjcRuntime.hpp"
#include "PredicateScanner.hpp"
#include "ObjcMethodXrefScanner.hpp"

#include "ObjcMethodXrefScanner.hpp"
#include "PredicateScanner.hpp"
#include "ObjcClassXrefScanner.hpp"
#include "SymbolWrapperScanner.hpp"
#include "AppInfoScanner.hpp"

using namespace std;
using namespace iblessing;

static bool fexists(string filename) {
    std::ifstream ifile(filename);
    return (bool)ifile;
}

ScannerDispatcher::ScannerDispatcher() {
    this->registerScanner("objc-msg-xref", []() {
        return new ObjcMethodXrefScanner("objc-msg-xref", "generate objc_msgSend xrefs record");
    });
    
    this->registerScanner("predicate", []() {
        return new PredicateScanner("predicate", "scan for NSPredicate xrefs and sql injection surfaces");
    });
    
    this->registerScanner("objc-class-xref", []() {
        return new ObjcClassXrefScanner("objc-class-xref", "scan for class xrefs");
    });
    
    this->registerScanner("symbol-wrapper", []() {
        return new SymbolWrapperScanner("symbol-wrapper", "detect symbol wrappers");
    });
    
    this->registerScanner("app-info", []() {
        return new AppInfoScanner("app-info", "extract app infos");
    });
}

vector<Scanner *> ScannerDispatcher::allScanners() {
    vector<Scanner *> scanners;
    for (auto it = scannerMap.begin(); it != scannerMap.end(); it++) {
        scanners.push_back(it->second());
    }
    return scanners;
}

void ScannerDispatcher::registerScanner(string scannerId, ScannerProvider provider) {
    scannerMap[scannerId] = provider;
}

int ScannerDispatcher::start(std::string scannerId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath) {
    Scanner *s = prepareForScanner(scannerId, options, inputPath, outputPath);
    if (!s) {
        return 1;
    }
    
    int ret = s->start();
    delete s;
    return ret;
}


Scanner* ScannerDispatcher::prepareForScanner(std::string scannerId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath) {
    // input validate
    if (!fexists(inputPath)) {
        cout << termcolor::red << "Error: input file " << inputPath << " not exist" << termcolor::reset << endl;
    }
    
    // scanner validate
    // FIXME: hardcode
    if (scannerMap.find(scannerId) == scannerMap.end()) {
        cout << termcolor::red << "Error: cannot find scanner " << scannerId << endl;
        return nullptr;
    }
    
    // here we go
    Scanner *s = scannerMap[scannerId]();
    
    // open file
    if (s->isBinaryScanner) {
        // map file
        int fd = open(inputPath.c_str(), O_RDWR);
        if (fd == -1) {
            cout << termcolor::red << "Error: invalid binary file " << inputPath << endl;
            return nullptr;
        }
        struct stat fileStatus;
        fstat(fd, &fileStatus);
        uint8_t *mappedFile = (uint8_t *)mmap(nullptr, fileStatus.st_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
        
    //    class Defer {
    //    public:
    //        std::function<void (void)> handler;
    //        Defer(std::function<void (void)> handler) {
    //            this->handler = handler;
    //        }
    //        ~Defer() {
    //            handler();
    //        }
    //    };
    //
    //    Defer _ = Defer([&]() {
    //        close(fd);
    //        munmap(mappedFile, fileStatus.st_size);
    //    });
        
        // read header
        struct mach_header_64 *hdr = (struct mach_header_64 *)mappedFile;
        uint32_t magic = hdr->magic;
        switch (magic) {
            case MH_MAGIC_64:
            case MH_CIGAM_64:
                cout << "[+] detect mach-o header 64" << endl;
                if (magic == MH_CIGAM_64) {
                    cout << "[+] detect big-endian, swap header to litten-endian" << endl;
                    swap_mach_header_64(hdr, NX_LittleEndian);
                } else {
                    cout << "[+] detect litten-endian" << endl;
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
            cout << termcolor::red << "Error: DYLD_INFO_ONLY segment not found, maybe the mach-o file is corrupted";
            cout << termcolor::reset << endl;
            return nullptr;
        }
        
        // sanity check
        if (!textSeg64) {
            cout << termcolor::red << "Error: __TEXT segment not found, maybe the mach-o file is corrupted";
            cout << termcolor::reset << endl;
            return nullptr;
        }
        
        // build string table
        if (symtab_cmd == nullptr) {
            cout << termcolor::red << "Error: SYMTAB segment not found, maybe the mach-o file is corrupted";
            cout << endl;
            return nullptr;
        }
        if (dysymtab_cmd == nullptr) {
            cout << termcolor::red << "Error: DYSYMTAB segment not found, maybe the mach-o file is corrupted";
            cout << endl;
            return nullptr;
        }
        
        StringTable *strtab = StringTable::getInstance();
        uint64_t strtab_vmaddr = linkedit_base + symtab_cmd->stroff;
        strtab->buildStringTable(strtab_vmaddr, mappedFile + symtab_cmd->stroff, symtab_cmd->strsize);
        
        // symtab vmaddr will be loaded base on linkedit_base
        SymbolTable *symtab = SymbolTable::getInstance();
        symtab->buildSymbolTable(mappedFile + symtab_cmd->symoff, symtab_cmd->nsyms);
        symtab->buildDynamicSymbolTable(sectionHeaders, mappedFile + dysymtab_cmd->indirectsymoff, dysymtab_cmd->nindirectsyms, mappedFile);
        symtab->sync();
    }
    
    // bind context
    s->dispatcher = this;
    
    // bind options
    s->inputPath = inputPath;
    vector<string> pathComponents = StringUtils::split(inputPath, '/');
    s->fileName = pathComponents[pathComponents.size() - 1];
    s->outputPath = outputPath;
    s->options = options;
    return s;
}
