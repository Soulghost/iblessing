//
//  darwin-file-system.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/11/15.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "darwin-file-system.hpp"
#include "macho-memory.hpp"
#include "aarch64-machine.hpp"
#include "uc_debugger_utils.hpp"
#include "StringUtils.h"
#include <algorithm>
#include <fstream>
#include <sys/fcntl.h>
#include <sys/socket.h>

using namespace std;
using namespace iblessing;

#pragma mark - DrawinFile start
int DarwinFile::fcntl(int cmd, uint64_t arg) {
    switch (cmd) {
        case F_GETFD:
            return op;
        case F_SETFD:
            if (FD_CLOEXEC == arg) {
                op |= FD_CLOEXEC;
                return 0;
            }
            break;
        case F_GETFL:
            return oflags;
        case F_SETFL:
            assert(false);
            return 0;
        case F_SETLK:
        case F_SETLKW:
        case F_ADDFILESIGS:
            return 0;
        case F_GETPATH: {
            uint64_t pathAddr = machine->loader->memoryManager->allocPath(path);
            ensure_uc_mem_write(arg, &pathAddr, sizeof(uint64_t));
            return 0;
        }
    }
    
    uc_debug_print_backtrace(uc);
    assert(false);
    return 0;
}

int DarwinFile::write(uint64_t bufferAddr, int count) {
    assert(false);
}

off_t DarwinFile::lseek(off_t offset, int whence) {
    switch (whence) {
        case SEEK_SET:
            this->seek = offset;
            break;
        case SEEK_CUR:
            this->seek += offset;
        case SEEK_END:
            this->seek = this->size + offset;
        default:
            break;
    }
    return this->seek;
}

#pragma mark - DarwinUdpSocket start
int DarwinUdpSocket::connect(uint64_t addrAddr, int addrlen) {
    uint8_t sa_len, sa_family;
    ensure_uc_mem_read(addrAddr, &sa_len, 1);
    ensure_uc_mem_read(addrAddr + 1, &sa_family, 1);
    assert(sa_family == AF_LOCAL);
    
    char *path = MachoMemoryUtils::uc_read_string(uc, addrAddr + 2, 1000);
    printf("[Stalker][+][Syscall] connect to local udp socket with fd %d, path %s\n", fd, path);
    this->path = string(path);
    free(path);
    return 0;
}

int DarwinUdpSocket::sendto(uint64_t bufferAddr, size_t length, int flags, uint64_t dest_addr, int dest_len) {
    assert(flags == 0 && dest_addr == 0 && dest_len == 0);
    char *buf = (char *)calloc(1, length + 1);
    ensure_uc_mem_read(bufferAddr, buf, length);
    printf("[Stalker][*][Syscall][File][Logger] log to %s: %s", path.c_str(), buf);
    free(buf);
    return 0;
}

int DarwinUdpSocket::write(uint64_t bufferAddr, int count) {
    char *buf = (char *)calloc(1, count + 1);
    ensure_uc_mem_read(bufferAddr, buf, count);
    printf("[Stalker][*][Syscall][File][Logger] log to %s: %s", path.c_str(), buf);
    free(buf);
    return 0;
}

off_t DarwinUdpSocket::lseek(off_t offset, int whence) {
    assert(false);
}

#pragma mark - DarwinFileSystem start
DarwinFileSystem::DarwinFileSystem(uc_engine *uc) {
    this->uc = uc;
    this->fdCounter = 1000;
}

int DarwinFileSystem::allocateFileDescriptor() {
    return this->fdCounter++;
}

int DarwinFileSystem::open(char *path, int oflags) {
    if (strcmp(path, "/etc/master.passwd") == 0) {
        shared_ptr<DarwinFile> f = make_shared<DarwinFile>();
        f->uc = uc;
        f->machine = machine;
        f->path = string(path);
        f->oflags = oflags;
        f->fd = allocateFileDescriptor();
        f->seek = 0;
        f->buf = strdup("root:p5Z3vjjEfs.bQ:0:0::0:0:System Administrator:/var/root:/bin/sh");
        f->size = strlen(f->buf);
        fd2file[f->fd] = f;
        return f->fd;
    } else if (strcmp(path, "/private/tmp/iblessing-workdir") == 0) {
        shared_ptr<DarwinFile> f = make_shared<DarwinFile>();
        f->uc = uc;
        f->machine = machine;
        f->path = string(path);
        f->oflags = oflags;
        f->fd = allocateFileDescriptor();
        f->seek = 0;
        f->buf = NULL;
        f->size = 1;
        fd2file[f->fd] = f;
        printf("[Stalker][-][Syscall][Warn] faked open workdir %s\n", path);
        return f->fd;
    } else if (StringUtils::has_prefix(string(path), "/System/Library/FeatureFlags/")) {
        static string featureFlagsRoot = "";
        if (featureFlagsRoot.length() == 0) {
            char *productRoot = getenv("IB_SOURCE_ROOT");
            featureFlagsRoot = StringUtils::format("%s/../ipsw/System/Library/FeatureFlags/", productRoot);
        }
        string realpath = string(path);
        StringUtils::replace(realpath, "/System/Library/FeatureFlags/", featureFlagsRoot);
        if (access(realpath.c_str(), F_OK) != 0) {
            machine->setErrno(ENOENT);
            printf("[Stalker][-][Syscall][File][Error] cannot open FeatureFlags file %s\n", path);
            return -1;
        }
        
        ifstream ifs(realpath);
        string content((std::istreambuf_iterator<char>(ifs)),
                       (std::istreambuf_iterator<char>()));
        
        shared_ptr<DarwinFile> f = make_shared<DarwinFile>();
        f->uc = uc;
        f->machine = machine;
        f->path = string(path);
        f->oflags = oflags;
        f->fd = allocateFileDescriptor();
        f->seek = 0;
        f->buf = strdup(content.c_str());
        f->size = strlen(f->buf);
        fd2file[f->fd] = f;
        return f->fd;
    }
    
    if (StringUtils::has_prefix(string(path), "/Library/Managed Preferences/") ||
        StringUtils::has_prefix(string(path), "/Library/Preferences")) {
        printf("[Stalker][-][Syscall][File][Warn] ignore open prefs file at %s\n", path);
        machine->setErrno(ENOENT);
        return -1;
    }
    
    machine->setErrno(ENOENT);
    printf("[Stalker][-][Syscall][File][Error] cannot open file %s\n", path);
    uc_debug_print_backtrace(uc);
    assert(false);
    return -1;
}

int DarwinFileSystem::openUdpSocket() {
    shared_ptr<DarwinUdpSocket> sock = make_shared<DarwinUdpSocket>();
    sock->uc = uc;
    int fd = allocateFileDescriptor();
    fd2file[fd] = sock;
    return fd;
}

int DarwinFileSystem::read(int fd, uint64_t bufferAddr, int count) {
    if (fd2file.find(fd) == fd2file.end()) {
        return -1;
    }
    
    shared_ptr<DarwinFile> f = fd2file[fd];
    if (f->type == DarwinFileTypePlain) {
        if (f->seek == f->size) {
            uint8_t nullbyte = 0;
            assert(uc_mem_write(uc, bufferAddr, &nullbyte, 1) == UC_ERR_OK);
            return 0;
        } else if (f->seek > f->size) {
            assert(false);
        }
        
        int rest = (int)(f->size - f->seek);
        int readCount = std::min(count, rest);
        string content = string(f->buf).substr(f->seek, readCount);
        assert(uc_mem_write(uc, bufferAddr, content.c_str(), readCount) == UC_ERR_OK);
        f->seek += readCount;
        return readCount;
    } else {
        assert(false);
    }
    return 0;
}

int DarwinFileSystem::pread(int fd, uint64_t bufferAddr, int count, off_t offset) {
    assert(has(fd));
    shared_ptr<DarwinFile> f = fd2file[fd];
    int64_t originSeek = f->seek;
    f->seek = offset;
    int result = read(fd, bufferAddr, count);
    f->seek = originSeek;
    return result;
}

int DarwinFileSystem::write(int fd, uint64_t bufferAddr, int count) {
    if (fd == 1 || fd == 2) {
        // stderr
        string type = (fd == 1 ? "STDOUT" : "STDERR") ;
        char *buf = (char *)calloc(1, count + 1);
        ensure_uc_mem_read(bufferAddr, buf, count);
        printf("%s[Logger][%s]: %s", SyscallBanner, type.c_str(), buf);
        free(buf);
        return 0;
    }
    
    assert(has(fd));
    shared_ptr<DarwinFile> file = fd2file[fd];
    return file->write(bufferAddr, count);
}

int DarwinFileSystem::close(int fd) {
    if (fd2file.find(fd) == fd2file.end()) {
        machine->setErrno(ENOENT);
        return -1;
    }
    
    // fs FIXME: clear file memory
    fd2file.erase(fd);
    return 0;
}

bool DarwinFileSystem::has(int fd) {
    return fd2file.find(fd) != fd2file.end();
}

int DarwinFileSystem::fcntl(int fd, int cmd, uint64_t arg) {
    assert(has(fd));
    shared_ptr<DarwinFile> file = fd2file[fd];
    return file->fcntl(cmd, arg);
}

int DarwinFileSystem::connect(int fd, uint64_t addrAddr, int addrlen) {
    assert(has(fd));
    shared_ptr<DarwinFile> file = fd2file[fd];
    return file->connect(addrAddr, addrlen);
}

int DarwinFileSystem::sendto(int socket, uint64_t bufferAddr, size_t length, int flags, uint64_t dest_addr, int dest_len) {
    assert(has(socket));
    shared_ptr<DarwinFile> file = fd2file[socket];
    return file->sendto(bufferAddr, length, flags, dest_addr, dest_len);
}

off_t DarwinFileSystem::lseek(int fd, off_t offset, int whence) {
    assert(has(fd));
    shared_ptr<DarwinFile> file = fd2file[fd];
    printf("[Stalker][*][Syscall][File] lseek for file %s, offset %lld, whence %d\n", file->path.c_str(), offset, whence);
    return file->lseek(offset, whence);
}
