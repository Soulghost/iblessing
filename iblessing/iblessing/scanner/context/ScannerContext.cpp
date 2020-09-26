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
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "VirtualMemory.hpp"
#include "VirtualMemoryV2.hpp"
#include "ObjcRuntime.hpp"
#include "StringTable.hpp"
#include "SymbolTable.hpp"
#include "StringUtils.h"

using namespace std;
using namespace iblessing;

ScannerContext::ScannerContext() {
    workDirManager.reset(new ScannerWorkDirManager("/tmp/iblessing-workdir"));
}

scanner_err ScannerContext::headerDetector(string binaryPath,
                                           uint8_t **mappedFileOut,    /** OUT */
                                           uint64_t *sizeOut,          /** OUT */
                                           ib_mach_header_64 **hdrOut  /** OUT */) {
    if (!mappedFileOut || !sizeOut || !hdrOut) {
        return SC_ERR_INVALID_ARGUMENTS;
    }
    
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
    
    uint64_t offset = 0, size = 0;
    scanner_err err = headerDetector(mappedFile, hdrOut, &offset, &size);
    if (err || !*hdrOut) {
        return err;
    }
    
    *mappedFileOut = (mappedFile + offset);
    *sizeOut = size == 0 ? fileStatus.st_size : size;
    return SC_ERR_OK;
}

scanner_err ScannerContext::headerDetector(uint8_t *mappedFile,
                                           ib_mach_header_64 **hdrOut,
                                           uint64_t *archOffsetOut,
                                           uint64_t *archSizeOut) {
    // read header
    struct ib_mach_header_64 *hdr = (struct ib_mach_header_64 *)mappedFile;
    uint32_t magic = hdr->magic;
    switch (magic) {
        case IB_MH_MAGIC_64:
        case IB_MH_CIGAM_64: {
//            cout << "[+] ScannerContext detect mach-o header 64" << endl;
            if (magic == IB_MH_CIGAM_64) {
//                cout << "[+] ScannerContext detect big-endian, swap header to litten-endian" << endl;
                ib_swap_mach_header_64(hdr, IB_LittleEndian);
            } else {
//                cout << "[+] ScannerContext detect litten-endian" << endl;
            }
            
            *hdrOut = hdr;
            if (archOffsetOut) {
                *archOffsetOut = 0;
            }
            if (archSizeOut) {
                *archSizeOut = 0;
            }
            break;
        }
        case IB_FAT_MAGIC:
        case IB_FAT_CIGAM: {
//            cout << "[+] ScannerContext - detect mach-o fat header 64" << endl;
            struct ib_fat_header *fat_hdr = (struct ib_fat_header *)mappedFile;
            bool needSwapHeader = false;
            if (magic == IB_FAT_CIGAM) {
//                cout << "[+] ScannerContext - detect big-endian, swap header to litten-endian" << endl;
                needSwapHeader = true;
                ib_swap_fat_header(fat_hdr, IB_LittleEndian);
            } else {
//                cout << "[+] ScannerContext - detect litten-endian" << endl;
            }
            
            // split aarch64
            uint32_t narchs = fat_hdr->nfat_arch;
            struct ib_fat_arch *arch = (struct ib_fat_arch *)(mappedFile + sizeof(struct ib_fat_header));
            uint64_t arch_hdr_offset = 0;
            for (uint32_t i = 0; i < narchs; i++) {
                if (needSwapHeader) {
                    ib_swap_fat_arch(arch, IB_LittleEndian);
                }
                if (arch->cputype == CPU_TYPE_ARM64) {
                    arch_hdr_offset = arch->offset;
                    break;
                }
                arch += 1;
            }
            
            if (arch_hdr_offset == 0) {
                return SC_ERR_UNSUPPORT_ARCH;
            }
            
            uint64_t firstByte = *(uint64_t *)(mappedFile + arch_hdr_offset);
            if (firstByte == *(uint64_t *)"!<arch>\n") {
                return SC_ERR_NEED_ARCHIVE;
            } else {
                hdr = (struct ib_mach_header_64 *)(mappedFile + arch_hdr_offset);
                *hdrOut = hdr;
                if (archOffsetOut) {
                    *archOffsetOut = arch->offset;
                }
                if (archSizeOut) {
                    *archSizeOut = arch->size;
                }
            }
            break;
        }
        default: {
            return SC_ERR_UNSUPPORT_ARCH;
        }
    }
    return SC_ERR_OK;
}

#pragma mark - setup
static scanner_err forkExec(string name, function<int (void)> woker) {
    pid_t childPid = fork();
    if (childPid == -1) {
        return SC_ERR_UNKNOWN;
    }
    
    int status = -1;
    if (childPid == 0) {
        exit(woker());
    } else {
        printf("[*] ScannerContext - waiting for %s process %d\n", name.c_str(), childPid);
        do {
            pid_t wpid = waitpid(childPid, &status, WNOHANG);
            if (wpid == childPid && status != -1) {
                break;
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }

    if (status != 0) {
        printf("[*] ScannerContext - %s failed with error code %d\n", name.c_str(), status);
        return SC_ERR_UNKNOWN;
    }
    
    printf("[*] ScannerContext - %s success\n", name.c_str());
    return SC_ERR_OK;
}

scanner_err ScannerContext::archiveStaticLibraryAndRetry(string binaryPath) {
    // mapping binary file
    cout << "[*] ScannerContext - detect static libary at " << binaryPath << endl;
    
    if (workDirManager->resetWorkDir() != 0) {
        return SC_ERR_RESET_WORK_DIR;
    }
    
    char *shadowFilePath = nullptr;
    if (workDirManager->createShadowFile(binaryPath, &shadowFilePath) != 0) {
        return SC_ERR_MAP_FAILED;
    }
    
    if (shadowFilePath == nullptr) {
        return SC_ERR_MAP_FAILED;
    }
    
    binaryPath = shadowFilePath;
    vector<string> pathComponents = StringUtils::split(binaryPath, '/');
    string fileName = pathComponents[pathComponents.size() - 1];
    printf("[*] ScannerContext - thinning file %s to arm64\n", shadowFilePath);
    
    scanner_err err = forkExec("lipo", [&]() {
        return execl("/usr/bin/lipo", "lipo", "-thin", "arm64", shadowFilePath, "-o", shadowFilePath, NULL);
    });
    if (err != SC_ERR_OK) {
        return err;
    }
    
    size_t size = pathconf(".", _PC_PATH_MAX);
    char *buf = (char *)malloc((size_t)size);
    char *pWorkDir = getcwd(buf, (size_t)size);
    string tmpWorkDir = workDirManager->getWorkDir();
    if (chdir(tmpWorkDir.c_str()) != 0) {
        return SC_ERR_UNKNOWN;
    }
    
    err = forkExec("ar", [&]() {
        return execl("/usr/bin/ar", "ar", "-x", shadowFilePath, NULL);
    });
    
    chdir(pWorkDir);
    free(buf);
    
    if (err != SC_ERR_OK) {
        return err;
    }
    
    vector<string> objectFiles = workDirManager->findAllObjectFiles({fileName});
    // 4 + o_size + 2 + 1 = o_size + 7
    size_t osize = objectFiles.size() + 7;
    char **argv = (char **)malloc(sizeof(char *) * osize);
    argv[0] = strdup("ld");
    argv[1] = strdup("-r");
    argv[2] = strdup("-arch");
    argv[3] = strdup("arm64");
    for (size_t i = 0; i < objectFiles.size(); i++) {
        argv[i + 4] = strdup(objectFiles[i].c_str());
    }
    argv[osize - 3] = strdup("-o");
    argv[osize - 2] = strdup(binaryPath.c_str());
    argv[osize - 1] = NULL;
    
    err = forkExec("ld", [&]() {
        return execv("/usr/bin/ld", argv);
    });
    
    for (int i = 0; i < osize; i++) {
        free(argv[i]);
    }
    free(argv);
    
    return setupWithBinaryPath(binaryPath, true);
}

scanner_err ScannerContext::setupWithBinaryPath(string binaryPath, bool reentry) {
    // mapping binary file
    if (reentry) {
        cout << "[+] ScannerContext - reentry from archiver" << endl;
    }
    cout << "[*] ScannerContext - load binary file at " << binaryPath << endl;
    
    char *shadowFilePath = nullptr;
    if (!reentry) {
        if (workDirManager->resetWorkDir() != 0) {
            return SC_ERR_RESET_WORK_DIR;
        }
        
        if (workDirManager->createShadowFile(binaryPath, &shadowFilePath) != 0) {
            return SC_ERR_MAP_FAILED;
        }
        
        if (shadowFilePath == nullptr) {
            return SC_ERR_MAP_FAILED;
        }
    } else {
        shadowFilePath = strdup(binaryPath.c_str());
    }
    
    string originPath = binaryPath;
    binaryPath = shadowFilePath;
    // create shadow file
    cout << "[*] ScannerContext - create shadow file at " << binaryPath << endl;
    
    uint8_t *mappedFile = nullptr;
    uint64_t fileSize = 0;
    ib_mach_header_64 *hdr = nullptr;
    scanner_err err = ScannerContext::headerDetector(binaryPath, &mappedFile, &fileSize, &hdr);
    if (err != SC_ERR_OK) {
        if (err != SC_ERR_NEED_ARCHIVE) {
            return err;
        }
        
        // avoid of deadloop
        if (reentry) {
            return SC_ERR_UNSUPPORT_ARCH;
        }
        
#ifdef IB_PLATFORM_DARWIN
        return archiveStaticLibraryAndRetry(originPath);
#else
        return SC_ERR_UNSUPPORT_ARCH;
#endif
    }
    
    // parse section headers
    // vmaddr base
    uint64_t vmaddr_base = 0;
    // symtab、dlsymtab、strtab's vmaddr base on LINKEDIT's vmaddr
    uint64_t linkedit_base = 0;
    uint64_t vmaddr_bss_start = 0;
    uint64_t vmaddr_bss_end = 0;
    
    uint32_t ncmds = hdr->ncmds;
    uint8_t *cmds = mappedFile + sizeof(struct ib_mach_header_64);
    // offset, symbolIdx, baseAddr
    vector<pair<pair<uint64_t, uint64_t>, uint64_t>> allRelocs;
    
    struct ib_symtab_command *symtab_cmd = nullptr;
    struct ib_dysymtab_command *dysymtab_cmd = nullptr;
    struct ib_segment_command_64 *textSeg64 = nullptr;
    struct ib_section_64 *textSect = nullptr;
    struct ib_entry_point_command *mainSeg = nullptr;
    struct ib_dyld_info_command *dyld_info = nullptr;
    uint64_t objc_classlist_addr = 0;
    uint64_t objc_classlist_size = 0;
    std::vector<struct ib_section_64 *> sectionHeaders;
    std::vector<struct ib_segment_command_64 *> segmentHeaders;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct ib_load_command *lc = (struct ib_load_command *)cmds;
        switch (lc->cmd) {
            case IB_LC_SEGMENT_64: {
                struct ib_segment_command_64 *seg64 = (struct ib_segment_command_64 *)lc;
                segmentHeaders.push_back(seg64);
                if (strncmp(seg64->segname, "__TEXT", 6) == 0) {
                    textSeg64 = seg64;
                    vmaddr_base = seg64->vmaddr - seg64->fileoff;
                } else if (strncmp(seg64->segname, "__LINKEDIT", 10) == 0) {
                    linkedit_base = seg64->vmaddr - seg64->fileoff;
                }
                
                if (seg64->nsects > 0) {
                    struct ib_section_64 *sect = (struct ib_section_64 *)((uint8_t *)seg64 + sizeof(struct ib_segment_command_64));
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
                        
                        if (sect->reloff > 0 && sect->nreloc > 0) {
                            allRelocs.push_back({{sect->reloff, sect->nreloc}, sect->addr});
                        }
                        
                        sectionHeaders.push_back(sect);
                        sect += 1;
                        
                    }
                }
                break;
            }
            case IB_LC_MAIN: {
                struct ib_entry_point_command *lc_main = (struct ib_entry_point_command *)lc;
                mainSeg = lc_main;
                break;
            }
            case IB_LC_SYMTAB: {
                symtab_cmd = (struct ib_symtab_command *)lc;
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
    
    VirtualMemory *vm = VirtualMemory::progressDefault();
    vm->vmaddr_base = vmaddr_base;
    vm->linkedit_base = linkedit_base;
    vm->vmaddr_bss_start = vmaddr_bss_start;
    vm->vmaddr_bss_end = vmaddr_bss_end;
    vm->mappedFile = mappedFile;
    vm->mappedSize = fileSize;
    vm->segmentHeaders = segmentHeaders;
    vm->dyldinfo = dyld_info;
    vm->textSect = textSect;
    vm->textSeg = textSeg64;
    
    // load vm-v2
    VirtualMemoryV2 *vm2 = VirtualMemoryV2::progressDefault();
    if (vm2->loadWithMachOData(mappedFile) != 0) {
        return SC_ERR_UNSUPPORT_ARCH;
    }

    // sort sectionHeaders by offset
    sort(sectionHeaders.begin(), sectionHeaders.end(), [&](struct ib_section_64 *a, struct ib_section_64 *b) {
        return a->offset < b->offset;
    });
    
    // build string table
    if (!symtab_cmd) {
        return SC_ERR_MACHO_MISSING_SEGMENT_SYMTAB;
    }
    
    StringTable *strtab = StringTable::getInstance();
    uint64_t strtab_vmaddr = linkedit_base + symtab_cmd->stroff;
    strtab->buildStringTable(strtab_vmaddr, mappedFile + symtab_cmd->stroff, symtab_cmd->strsize);
    
    // symtab vmaddr will be loaded base on linkedit_base
    SymbolTable *symtab = SymbolTable::getInstance();
    symtab->buildSymbolTable(mappedFile + symtab_cmd->symoff, symtab_cmd->nsyms);
    if (dysymtab_cmd) {
        symtab->buildDynamicSymbolTable(sectionHeaders, mappedFile + dysymtab_cmd->indirectsymoff, dysymtab_cmd->nindirectsyms, mappedFile);
    }
    
    
    if (allRelocs.size() > 0) {
        for (pair<pair<uint64_t, uint64_t>, uint64_t> &reloc : allRelocs) {
            uint64_t relocAddr = reloc.first.first;
            uint64_t relocCount = reloc.first.second;
            uint64_t relocBase = reloc.second;
            
            struct scattered_relocation_info *reloc_info = (struct scattered_relocation_info *)(mappedFile + relocAddr);
            while (relocCount--) {
                uint64_t addr =  relocBase + (reloc_info->r_address & 0x00ffffff);
                uint64_t symbolNum = (reloc_info->r_value & 0x00ffffff);
                symtab->relocSymbol(addr, symbolNum);
                reloc_info++;
            }
        }
    }
    symtab->sync();
    vm2->relocAllRegions();
    
    ObjcRuntime *objcRuntime = ObjcRuntime::getInstance();
    objcRuntime->loadClassList(objc_classlist_addr, objc_classlist_size);
    
    return SC_ERR_OK;
}

#pragma mark - Getter
string ScannerContext::getBinaryPath() {
    return binaryPath;
}
