//
//  darwin-file-system.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/11/15.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "darwin-file-system.hpp"
#include "macho-memory.hpp"
#include <algorithm>
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
    }
    assert(false);
    return 0;
}

int DarwinFile::write(uint64_t bufferAddr, int count) {
    assert(false);
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
    printf("%s[Logger] log to %s: %s", SyscallBanner, path.c_str(), buf);
    free(buf);
    return 0;
}

int DarwinUdpSocket::write(uint64_t bufferAddr, int count) {
    char *buf = (char *)calloc(1, count + 1);
    ensure_uc_mem_read(bufferAddr, buf, count);
    printf("%s[Logger] log to %s: %s", SyscallBanner, path.c_str(), buf);
    free(buf);
    return 0;
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
        f->path = string(path);
        f->oflags = oflags;
        f->fd = allocateFileDescriptor();
        f->seek = 0;
        f->buf = strdup("root:p5Z3vjjEfs.bQ:0:0::0:0:System Administrator:/var/root:/bin/sh");
        f->size = strlen(f->buf);
        fd2file[f->fd] = f;
        return f->fd;
    }
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
        return ENOENT;
    }
    
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
