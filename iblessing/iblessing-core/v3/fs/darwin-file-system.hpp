//
//  darwin-file-system.hpp
//  iblessing-core
//
//  Created by soulghost on 2021/11/15.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef darwin_file_system_hpp
#define darwin_file_system_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <map>
#include <memory>

NS_IB_BEGIN

class Aarch64Machine;

enum DarwinFileType {
    DarwinFileTypePlain = 0,
    DarwinFileTypeUDPSocket
};

class DarwinFile {
public:
    std::shared_ptr<Aarch64Machine> machine;
    uc_engine *uc;
    int type;
    int op;
    int oflags;
    std::string path;
    int fd;
    uint64_t seek;
    char *buf;
    uint64_t size;
    
    DarwinFile() {
        op = oflags = 0;
        type = DarwinFileTypePlain;
    }
    
    virtual int fcntl(int cmd, uint64_t arg);
    virtual int write(uint64_t bufferAddr, int count);
    virtual off_t lseek(off_t offset, int whence);
    virtual int connect(uint64_t addrAddr, int addrlen) {
        assert(false);
    }
    virtual int sendto(uint64_t bufferAddr, size_t length, int flags, uint64_t dest_addr, int dest_len) {
        assert(false);
    }

};

class DarwinUdpSocket : public DarwinFile {
public:
    DarwinUdpSocket() {
        type = DarwinFileTypeUDPSocket;
    }
    
    virtual int connect(uint64_t addrAddr, int addrlen);
    virtual int write(uint64_t bufferAddr, int count);
    virtual int sendto(uint64_t bufferAddr, size_t length, int flags, uint64_t dest_addr, int dest_len);
    virtual off_t lseek(off_t offset, int whence);
};

class DarwinFileSystem {
public:
    std::shared_ptr<Aarch64Machine> machine;
    
    DarwinFileSystem(uc_engine *uc);
    
    int open(char *path, int oflags);
    int openUdpSocket();
    int pread(int fd, uint64_t bufferAddr, int count, off_t offset);
    int read(int fd, uint64_t bufferAddr, int count);
    int write(int fd, uint64_t bufferAddr, int count);
    int close(int fd);
    bool has(int fd);
    int fcntl(int fd, int cmd, uint64_t arg);
    int connect(int fd, uint64_t addrAddr, int addrlen);
    int sendto(int socket, uint64_t bufferAddr, size_t length, int flags, uint64_t dest_addr, int dest_len);
    off_t lseek(int fd, off_t offset, int whence);
    
protected:
    uc_engine *uc;
    int fdCounter;
    std::map<int, std::shared_ptr<DarwinFile>> fd2file;
    
    int allocateFileDescriptor();
    std::shared_ptr<DarwinFile> createFileWithPath(std::string path, int oflags);
};

NS_IB_END

#endif /* darwin_file_system_hpp */
