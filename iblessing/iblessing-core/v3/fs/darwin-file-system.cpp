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
            assert(path.length() < 1024); // max buffer size in _xpc_realpath_fd
            ensure_uc_mem_write(arg, path.c_str(), path.length() + 1);
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
//    if (path == "/var/run/syslog" && string(buf).find("notify_register_check failed with")) {
//        uc_debug_breakhere(uc);
//        assert(false);
//    }
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

shared_ptr<DarwinFile> DarwinFileSystem::createFileWithPath(string path, int oflags) {
    FILE *file = fopen(path.c_str(), "r");
    assert(file != NULL);
    
    fseek(file, 0, SEEK_END);
    uint64_t fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    void *buffer = calloc(fileLen, sizeof(char));
    assert(buffer != NULL);
    
    fread(buffer, sizeof(char), fileLen, file);
    fclose(file);
    
    shared_ptr<DarwinFile> f = make_shared<DarwinFile>();
    f->uc = uc;
    f->machine = machine;
    f->path = string(path);
    f->oflags = oflags;
    f->fd = allocateFileDescriptor();
    f->seek = 0;
    f->buf = (char *)buffer;
    f->size = fileLen;
    fd2file[f->fd] = f;
    return f;
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
        shared_ptr<DarwinFile> f = createFileWithPath(realpath, oflags);
        return f->fd;
    }
    
    if (StringUtils::has_prefix(string(path), "/Library/Managed Preferences/") ||
        StringUtils::has_prefix(string(path), "/Library/Preferences")) {
        printf("[Stalker][-][Syscall][File][Warn] ignore open prefs file at %s\n", path);
        machine->setErrno(ENOENT);
        return -1;
    }
    
    if (StringUtils::has_prefix(string(path), "/private/tmp/iblessing-workdir/")) {
        static string appBundlePath = "";
        if (appBundlePath.length() == 0) {
            char *productRoot = getenv("IB_SOURCE_ROOT");
            appBundlePath = StringUtils::format("%s/../app-bundle/", productRoot);
        }
        string realpath = string(path);
        StringUtils::replace(realpath, "/private/tmp/iblessing-workdir/", appBundlePath);
        if (access(realpath.c_str(), F_OK) != 0) {
            machine->setErrno(ENOENT);
            printf("[Stalker][-][Syscall][Logger][File][Error] cannot open app bundle file %s\n", path);
            return -1;
        }
        shared_ptr<DarwinFile> f = createFileWithPath(realpath, oflags);
        return f->fd;
    }
    if (StringUtils::has_prefix(string(path), "/etc/")) {
        static string folderPath = "";
        if (folderPath.length() == 0) {
            char *productRoot = getenv("IB_SOURCE_ROOT");
            folderPath = StringUtils::format("%s/../rootfs/etc/", productRoot);
        }
        string realpath = string(path);
        StringUtils::replace(realpath, "/etc/", folderPath);
        if (access(realpath.c_str(), F_OK) != 0) {
            machine->setErrno(ENOENT);
            printf("[Stalker][-][Syscall][Logger][File][Error] cannot open file %s\n", path);
            return -1;
        }
        shared_ptr<DarwinFile> f = createFileWithPath(realpath, oflags);
        return f->fd;
    }
    
    machine->setErrno(ENOENT);
    printf("[Stalker][-][Syscall][Logger][File][Error] cannot open file %s\n", path);
    if (strcmp(path, "/etc/.mdns_debug") == 0 ||
        strcmp(path, "/dev/autofs_nowait") == 0 ||
        strcmp(path, "/var/mobile/.CFUserTextEncoding") == 0) {
        // allowed
        return -1;
    }
    
    if (strcmp(path, "/System/Library/Preferences/Logging/Processes/com.soulghost.iblessing.iblessing-sample.plist") == 0) {
        // allowed
        return -1;
    }
    
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
        uint64_t readStart = f->seek;
        ensure_uc_mem_write(bufferAddr, f->buf + readStart, readCount);
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
        if (uc_mem_read(uc, bufferAddr, buf, count) != UC_ERR_OK) {
            uc_debug_breakhere(uc);
        }
//        ensure_uc_mem_read(bufferAddr, buf, count);
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

int DarwinFileSystem::fstat(int fd, uint64_t statBufAddr) {
    assert(has(fd));
    int st_mode;
    if (fd == 1) {
        st_mode = S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO;
    } else {
        st_mode = S_IFREG;
    }
    
    shared_ptr<DarwinFile> file = fd2file[fd];
    struct posix_timesec {
        long tv_sec;
        long tv_nsec;
    };
    struct posix_stat {
        dev_t     st_dev;     /* ID of device containing file 32 */
        mode_t    st_mode;    /* protection 16 */
        nlink_t   st_nlink;   /* number of hard links 16 */
        ino_t     st_ino;     /* inode number 64 */
        uid_t     st_uid;     /* user ID of owner 32 */
        gid_t     st_gid;     /* group ID of owner 32 */
        dev_t     st_rdev;    /* device ID (if special file) 32 */
        struct posix_timesec st_atimespec;  /* time of last access */
        struct posix_timesec st_mtimespec;  /* time of last data modification */
        struct posix_timesec st_ctimespec;  /* time of last status change */
        struct posix_timesec st_birthtimespec; /* time of file creation(birth) */
        off_t     st_size;    /* total size, in bytes */
        blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
        blksize_t st_blksize; /* blocksize for file system I/O */
        uint32_t    st_flags; /* user defined flags for file */
        uint32_t    st_gen;   /* file generation number */
    };
    struct posix_stat s = { 0 };
    blksize_t blockSize = 0x4000;
    s.st_dev = 1;
    s.st_mode = st_mode;
    s.st_size = file->size;
    s.st_blocks = (s.st_size + blockSize - 1) / blockSize;
    s.st_blksize = blockSize;
    s.st_ino = 7;
    s.st_uid = 2333;
    s.st_gid = 2333;
    assert(uc_mem_write(uc, statBufAddr, &s, sizeof(struct posix_stat)) == UC_ERR_OK);
    return 0;
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
//    assert(has(fd));
    if (!has(fd)) {
        uc_debug_print_backtrace(uc);
        assert(false);
    }
    shared_ptr<DarwinFile> file = fd2file[fd];
    printf("[Stalker][*][Syscall][File] lseek for file %s, offset %lld, whence %d\n", file->path.c_str(), offset, whence);
    return file->lseek(offset, whence);
}
