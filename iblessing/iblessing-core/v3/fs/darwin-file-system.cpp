//
//  darwin-file-system.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/11/15.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "darwin-file-system.hpp"
#include <algorithm>

using namespace std;
using namespace iblessing;

DarwinFileSystem::DarwinFileSystem(uc_engine *uc) {
    this->uc = uc;
    this->fdCounter = 1000;
}

int DarwinFileSystem::open(char *path, int oflags) {
    if (strcmp(path, "/etc/master.passwd") == 0) {
        shared_ptr<DarwinFile> f = make_shared<DarwinFile>();
        f->path = string(path);
        f->fd = (this->fdCounter++);
        f->seek = 0;
        f->buf = strdup("root:p5Z3vjjEfs.bQ:0:0::0:0:System Administrator:/var/root:/bin/sh");
        f->size = strlen(f->buf);
        fd2file[f->fd] = f;
        return f->fd;
    }
    return -1;
}

int DarwinFileSystem::read(int fd, uint64_t bufferAddr, int count) {
    if (fd2file.find(fd) == fd2file.end()) {
        return -1;
    }
    
    shared_ptr<DarwinFile> f = fd2file[fd];
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
}

int DarwinFileSystem::write(int fd, uint64_t bufferAddr, int count) {
    return 0;
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
